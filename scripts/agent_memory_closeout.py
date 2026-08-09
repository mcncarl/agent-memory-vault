#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_memory_env import env_value, expand_path, load_config
from agent_memory_lock import try_lock, unlock
from agent_memory_claim import (
    active_claim_rows,
    all_active_claim_rows,
    complete_claim_paths,
    parse_deleted_observation,
    record_file_observations,
)
from agent_memory_safety import KNOWLEDGE_KINDS, SOURCE_CLASSES, assess_source, record_assessment
from agent_memory_state import POSIX_PERMISSION_MODEL, secure_append_text, secure_sqlite_connect
import agent_memory_intent as write_intent


SCRIPT_ROOT = Path(__file__).resolve().parent
TEMPLATE_REPO_ROOT = SCRIPT_ROOT.parent
DEFAULT_VAULT_ROOT = TEMPLATE_REPO_ROOT / "templates" / "vault"
VAULT_ROOT = expand_path(env_value("ROOT", str(DEFAULT_VAULT_ROOT))).resolve()
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()
STATE_DB = expand_path(env_value("STATE_DB", str(CONFIG_ROOT / "state.sqlite"))).resolve()
LOG_PATH = expand_path(env_value("CLOSEOUT_LOG", str(CONFIG_ROOT / "logs" / "closeout.jsonl"))).resolve()
LOCK_PATH = CONFIG_ROOT / "locks" / "closeout.lock"


def find_default_git_root() -> Path:
    for candidate in (VAULT_ROOT, *VAULT_ROOT.parents):
        if (candidate / ".git").exists():
            return candidate.resolve()
    return VAULT_ROOT.parent.resolve()


REPO_ROOT = expand_path(env_value("GIT_ROOT", str(find_default_git_root()))).resolve()

CHECK_SCRIPT = SCRIPT_ROOT / "agent_memory_check.py"
INDEX_SCRIPT = SCRIPT_ROOT / "agent_memory_index.py"
SEARCH_SCRIPT = SCRIPT_ROOT / "agent_memory_search.py"
ZVEC_SCRIPT = SCRIPT_ROOT / "agent_memory_zvec_index.py"
AGENT_EVOLUTION_SCRIPT = SCRIPT_ROOT / "agent_memory_evolution.py"
AUDIT_AUTORUN_SCRIPT = SCRIPT_ROOT / "agent_memory_audit_autorun.py"
PYTHON = env_value("PYTHON", sys.executable)
ZVEC_PYTHON = env_value("ZVEC_PYTHON", PYTHON)
SEMANTIC_CONFIG = load_config().get("semantic_retrieval", {})
SEMANTIC_ENABLED = bool(SEMANTIC_CONFIG.get("enabled", False)) if isinstance(SEMANTIC_CONFIG, dict) else False

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
NONCURRENT_RECONCILE_STATUSES = {"archived", "outdated", "superseded", "deleted"}
NONFACT_RECONCILE_TYPES = {"directory_index", "routing", "template", "open_loop"}


@dataclass
class GitEntry:
    status: str
    repo_path: str
    path: Path
    previous_repo_path: str = ""

    @property
    def exists(self) -> bool:
        return self.path.exists()

    @property
    def is_deleted(self) -> bool:
        return "D" in self.status

    @property
    def is_new(self) -> bool:
        return self.status == "??" or "A" in self.status or self.status.startswith("C")

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


@dataclass(frozen=True)
class CommitSnapshot:
    path: Path
    repo_path: str
    raw_sha256: str
    blob_oid: str
    mode: str


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def normalized_actor(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower()).strip("-")
    return cleaned or "unknown"


def session_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if value else ""


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
    input_text: str | None = None,
) -> dict[str, Any]:
    command_env = os.environ.copy() if env is None else env.copy()
    command_env.setdefault("PYTHONIOENCODING", "utf-8")
    command_env.setdefault("PYTHONUTF8", "1")
    started_at = utc_now()
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            input=input_text,
            timeout=timeout,
            env=command_env,
            check=False,
        )
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_ms": round((time.monotonic() - started) * 1000),
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
            "duration_ms": round((time.monotonic() - started) * 1000),
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
            "duration_ms": round((time.monotonic() - started) * 1000),
            "ok": False,
        }


@contextlib.contextmanager
def closeout_lock(timeout: float = 15.0):
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+", encoding="utf-8") as handle:
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            try:
                if try_lock(handle):
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError(f"another memory closeout is still running: {LOCK_PATH}")
            time.sleep(0.1)
        try:
            yield
        finally:
            unlock(handle)


def decode_status_line(line: str) -> GitEntry | None:
    if len(line) < 4:
        return None
    status = line[:2].strip() or line[:2]
    repo_path = line[3:]
    if " -> " in repo_path:
        repo_path = repo_path.split(" -> ", 1)[1]
    path = (REPO_ROOT / repo_path).resolve()
    return GitEntry(status=status, repo_path=repo_path, path=path)


def repo_path_in_vault(repo_path: str) -> bool:
    try:
        vault_repo_path = VAULT_ROOT.relative_to(REPO_ROOT).as_posix().rstrip("/")
    except ValueError:
        return False
    candidate = Path(repo_path).as_posix().lstrip("./")
    if vault_repo_path in {"", "."}:
        return True
    return candidate == vault_repo_path or candidate.startswith(f"{vault_repo_path}/")


def repo_path_is_memory_markdown(repo_path: str) -> bool:
    if not repo_path_in_vault(repo_path):
        return False
    return GitEntry(
        status="",
        repo_path=repo_path,
        path=(REPO_ROOT / repo_path).resolve(),
    ).is_memory_markdown


def git_status_entries() -> tuple[list[GitEntry], list[str]]:
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
        previous_repo_path = ""
        if entry and entry.status.startswith(("R", "C")) and index + 1 < len(items):
            previous_repo_path = items[index + 1]
            index += 1
        if entry:
            if repo_path_is_memory_markdown(entry.repo_path):
                entry.previous_repo_path = previous_repo_path
                entries.append(entry)
            elif entry.status.startswith("R") and repo_path_is_memory_markdown(previous_repo_path):
                old_path = (REPO_ROOT / previous_repo_path).resolve()
                entries.append(GitEntry(status="D", repo_path=previous_repo_path, path=old_path))
        index += 1
    return entries, []


def current_git_head() -> tuple[str, list[str]]:
    result = run_command(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], timeout=30)
    if not result["ok"]:
        return "", [f"git rev-parse failed: {str(result['stderr']).strip()}"]
    return str(result["stdout"]).strip(), []


def last_observed_git_head() -> str:
    if not LOG_PATH.exists():
        return ""
    try:
        lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("status") != "ok":
            continue
        for key in ("git_observed_through", "git_head_after", "commit"):
            value = str(item.get(key, ""))
            if value and value != "skipped" and re.fullmatch(r"[0-9a-fA-F]{7,40}", value):
                return value
    return ""


def git_history_entries(baseline: str, head: str) -> tuple[list[GitEntry], list[str]]:
    if not baseline or not head or baseline == head:
        return [], []
    ancestor = run_command(["git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor", baseline, head], timeout=30)
    if ancestor["returncode"] != 0:
        return [], [f"closeout git baseline is not an ancestor of HEAD: baseline={baseline[:12]} head={head[:12]}"]
    result = run_command(
        [
            "git", "-C", str(REPO_ROOT), "-c", "core.quotepath=false",
            "diff", "--find-renames", "--name-status", "-z", f"{baseline}..{head}",
        ],
        timeout=60,
    )
    if not result["ok"]:
        return [], [f"git history diff failed: {str(result['stderr']).strip()}"]
    items = [item for item in str(result["stdout"]).split("\0") if item]
    entries: list[GitEntry] = []
    index = 0
    while index < len(items):
        status = items[index]
        index += 1
        if index >= len(items):
            break
        if status.startswith(("R", "C")):
            if index + 1 >= len(items):
                break
            previous_repo_path = items[index]
            index += 1
            repo_path = items[index]
            index += 1
        else:
            previous_repo_path = ""
            repo_path = items[index]
            index += 1
        if repo_path_is_memory_markdown(repo_path):
            entries.append(
                GitEntry(
                    status=status,
                    repo_path=repo_path,
                    path=(REPO_ROOT / repo_path).resolve(),
                    previous_repo_path=previous_repo_path,
                )
            )
        elif status.startswith("R") and repo_path_is_memory_markdown(previous_repo_path):
            old_path = (REPO_ROOT / previous_repo_path).resolve()
            entries.append(GitEntry(status="D", repo_path=previous_repo_path, path=old_path))
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
            repo_path = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            warnings.append(f"changed file outside repo skipped: {path}")
            continue
        if not repo_path_is_memory_markdown(repo_path):
            warnings.append(f"changed non-memory file skipped: {path}")
            continue
        status = "??" if path.exists() else "D"
        entries.append(GitEntry(status=status, repo_path=repo_path, path=path))
    return entries, warnings


def relative_to_vault(path: Path) -> str:
    try:
        return path.relative_to(VAULT_ROOT).as_posix()
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


def without_frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return text
    end = text.find("\n---", 3)
    if end == -1:
        return text
    return text[end + 4 :].lstrip("\r\n")


def summary_from_text(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("summary:"):
            return stripped.split(":", 1)[1].strip().strip('"')
    current_summary = text.find("## 当前有效摘要")
    if current_summary != -1:
        section = text[current_summary + len("## 当前有效摘要") :]
        next_heading = re.search(r"\n##\s+", section)
        if next_heading is not None:
            section = section[: next_heading.start()]
        lines = [line.strip() for line in section.splitlines() if line.strip()]
        return " ".join(lines)[:500]
    body = without_frontmatter(text)
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    return " ".join(lines[:8])[:700]


def frontmatter_list(path: Path, key: str) -> set[str]:
    text = read_text(path)
    if not text.startswith("---"):
        return set()
    end = text.find("\n---", 3)
    if end == -1:
        return set()
    values: list[str] = []
    current_key = ""
    for line in text[3:end].splitlines():
        if re.match(r"^\s+-\s+", line) and current_key == key:
            values.append(re.sub(r"^\s+-\s+", "", line).strip())
            continue
        if line.startswith(" ") or ":" not in line:
            continue
        current_key, raw_value = line.split(":", 1)
        current_key = current_key.strip()
        if current_key != key:
            continue
        raw_value = raw_value.strip()
        if raw_value.startswith("[") and raw_value.endswith("]"):
            values.extend(item.strip() for item in raw_value[1:-1].split(","))
        elif raw_value:
            values.append(raw_value)
    return {value.strip().strip("'\"`") for value in values if value.strip()}


def reconcile_query_for_file(path: Path) -> str:
    text = read_text(path)
    title = title_from_text(text, path)
    summary = summary_from_text(text)
    query = f"{title} {summary}".strip()
    return query[:900]


def is_current_reconcile_target(path: Path) -> bool:
    statuses = {value.lower() for value in frontmatter_list(path, "status")}
    return not bool(statuses & NONCURRENT_RECONCILE_STATUSES)


def project_scope_for_file(path: Path, explicit_project: str = "") -> str:
    if explicit_project.strip():
        return explicit_project.strip()
    tracks = {value.casefold() for value in frontmatter_list(path, "track")}
    if "project" not in tracks:
        return ""
    project_ids = sorted(frontmatter_list(path, "project_id"))
    return project_ids[0] if len(project_ids) == 1 else ""


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


def search_memory(
    query: str,
    limit: int = 8,
    no_zvec: bool = True,
    current_project: str = "",
    read_only: bool = False,
    app_id: str = "",
    agent_scope: str = "",
    project_id: str = "",
) -> tuple[list[dict[str, Any]], list[str]]:
    command = [PYTHON, str(SEARCH_SCRIPT), "--query-stdin", "--limit", str(limit), "--json"]
    if no_zvec:
        command.append("--no-zvec")
    if current_project.strip():
        command.extend(["--current-project", current_project.strip()])
    if app_id.strip():
        command.extend(["--app-id", app_id.strip()])
    if agent_scope.strip():
        command.extend(["--agent-scope", agent_scope.strip()])
    if project_id.strip():
        command.extend(["--project-id", project_id.strip()])
    if read_only:
        command.append("--no-log")
    result = run_command(
        command,
        timeout=80,
        env=command_env_offline(),
        input_text=query,
    )
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


def semantic_distance(row: dict[str, Any]) -> float | None:
    """Return raw semantic distance only; adjusted rank scores are never evidence."""
    details = row.get("source_details")
    if not isinstance(details, dict):
        return None
    try:
        return float(details.get("zvec_raw_distance"))
    except (TypeError, ValueError):
        return None


def raw_semantic_distance(row: dict[str, Any]) -> float | None:
    return semantic_distance(row)


def rank_semantic_score(row: dict[str, Any]) -> float | None:
    details = row.get("source_details")
    if not isinstance(details, dict):
        return None
    for key in ("zvec_rank_distance", "zvec_rank_score", "zvec_score"):
        try:
            value = details.get(key)
            if value is not None:
                return float(value)
        except (TypeError, ValueError):
            continue
    return None


def prewrite_recommendation(text: str, rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None, dict[str, Any]]:
    if not rows:
        return "ADD", None, {"similarity": 0.0, "coverage": 0.0, "semantic_distance": None, "raw_semantic_distance": None}
    candidates: list[tuple[int, float, float, float, str, dict[str, Any]]] = []
    action_priority = {"NOOP": 4, "UPDATE": 3, "MERGE_REQUIRED": 2, "ADD": 1}
    for row in rows:
        comparison = " ".join(
            str(row.get(key, ""))
            for key in ("title", "rel_path", "summary", "hit")
        )
        similarity = jaccard(text, comparison)
        row_coverage = coverage(text, comparison)
        distance = raw_semantic_distance(row)
        if similarity >= 0.80 or row_coverage >= 0.90:
            action = "NOOP"
        elif similarity >= 0.45 or row_coverage >= 0.55 or (distance is not None and distance <= 0.32):
            action = "UPDATE"
        elif similarity >= 0.28 or row_coverage >= 0.35 or (distance is not None and distance <= 0.55):
            action = "MERGE_REQUIRED"
        else:
            action = "ADD"
        semantic_quality = 1.0 - distance if distance is not None else -1.0
        candidates.append((action_priority[action], semantic_quality, row_coverage, similarity, action, row))
    _, _, best_coverage, best_similarity, action, best_row = max(candidates, key=lambda item: item[:4])
    distance = semantic_distance(best_row)
    raw_distance = raw_semantic_distance(best_row)
    return action, best_row, {"similarity": best_similarity, "coverage": best_coverage, "semantic_distance": distance, "raw_semantic_distance": raw_distance}


def run_prewrite(args: argparse.Namespace) -> dict[str, Any]:
    run_id = uuid.uuid4().hex
    hashed_session = session_hash(args.session_id)
    safety = assess_source(
        args.prewrite,
        source_class=args.source_class,
        knowledge_kind=args.knowledge_kind,
        asserted_by=args.asserted_by or args.actor,
        evidence_ref=args.evidence_ref,
    )
    try:
        safety_audit_id = record_assessment(
            STATE_DB,
            safety,
            run_id=run_id,
            actor=args.actor,
            session_hash=hashed_session,
            trigger=args.trigger,
        )
        safety["audit_recorded"] = True
        safety["audit_id"] = safety_audit_id
    except (OSError, sqlite3.Error) as exc:
        safety["audit_recorded"] = False
        safety["audit_error"] = type(exc).__name__
        safety["decision"] = "BLOCK"
        safety["reason_code"] = "SAFETY_AUDIT_UNAVAILABLE"
        safety["can_reconcile"] = False
        safety["can_create_intent"] = False
    if safety["decision"] != "ALLOW":
        return {
            "time": utc_now(),
            "run_id": run_id,
            "actor": args.actor,
            "trigger": args.trigger,
            "session_hash": hashed_session,
            "mode": "prewrite",
            "input_sha256": safety["input_sha256"],
            "input_length": safety["input_length"],
            "safety": safety,
            "reconcile": {"status": "skipped", "reason_code": safety["reason_code"]},
            "recommended_action": "ASK_USER" if safety["decision"] == "ASK_USER" else "BLOCK",
            "recommended_target": None,
            "recommendation_metrics": {
                "similarity": 0.0,
                "coverage": 0.0,
                "semantic_distance": None,
                "raw_semantic_distance": None,
            },
            "allowed_actions": sorted(RECONCILE_ACTIONS),
            "candidates": [],
            "warnings": [safety["reason_code"]],
            "status": "warning" if safety["decision"] == "ASK_USER" else "blocked",
        }
    inferred_project = ""
    if getattr(args, "proposal_file", ""):
        inferred_project = project_scope_for_file(
            Path(args.proposal_file).expanduser(),
            getattr(args, "current_project", ""),
        )
    rows, warnings = search_memory(
        args.prewrite,
        limit=args.limit,
        no_zvec=args.no_zvec,
        current_project=inferred_project or getattr(args, "current_project", ""),
    )
    action, target, metrics = prewrite_recommendation(args.prewrite, rows)
    intent_payload: dict[str, Any] | None = None
    intent_error = ""
    if args.create_intent:
        if action == "NOOP":
            warnings.append("NOOP_REQUIRES_NO_WRITE_INTENT")
        elif not args.target_file or not args.proposal_file:
            intent_error = "INTENT_TARGET_AND_PROPOSAL_REQUIRED"
        elif not args.session_id:
            intent_error = "INTENT_SESSION_REQUIRED"
        else:
            try:
                intent_payload = write_intent.create_intent(
                    actor=args.actor,
                    raw_session_id=args.session_id,
                    target=args.target_file,
                    proposal_file=args.proposal_file,
                    approval_required=action in {"ASK_USER", "MERGE_REQUIRED"},
                    source_class=args.source_class,
                    knowledge_kind=args.knowledge_kind,
                    asserted_by=args.asserted_by or args.actor,
                    evidence_ref_sha256=str(safety.get("evidence_ref_sha256", "")),
                    reconcile_action=action,
                )
            except (write_intent.IntentError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
                intent_error = str(getattr(exc, "reason_code", "INTENT_CREATE_FAILED"))
                warnings.append(intent_error)
    return {
        "time": utc_now(),
        "run_id": run_id,
        "actor": args.actor,
        "trigger": args.trigger,
        "session_hash": hashed_session,
        "mode": "prewrite",
        "input_sha256": safety["input_sha256"],
        "input_length": safety["input_length"],
        "safety": safety,
        "reconcile": {
            "status": "completed",
            "recommended_action": action,
            "recommended_target": target.get("rel_path", "") if isinstance(target, dict) else "",
        },
        "write_intent": intent_payload,
        "write_intent_error": intent_error,
        "recommended_action": action,
        "recommended_target": target,
        "recommendation_metrics": {
            "similarity": round(metrics["similarity"], 4),
            "coverage": round(metrics["coverage"], 4),
            "semantic_distance": round(metrics["semantic_distance"], 4) if metrics["semantic_distance"] is not None else None,
            "raw_semantic_distance": round(metrics["raw_semantic_distance"], 4) if metrics["raw_semantic_distance"] is not None else None,
        },
        "allowed_actions": sorted(RECONCILE_ACTIONS),
        "candidates": rows,
        "warnings": warnings,
        "status": "blocked" if intent_error else ("warning" if action in {"ASK_USER", "MERGE_REQUIRED"} else "ok"),
    }


def postwrite_reconcile(entries: list[GitEntry], args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []
    targets = [
        entry
        for entry in entries
        if entry.exists
        and entry.is_memory_markdown
        and (entry.is_new or args.reconcile_all)
        and is_current_reconcile_target(entry.path)
    ]
    for entry in targets:
        declared_relations = frontmatter_list(entry.path, "related_workflows")
        query = reconcile_query_for_file(entry.path)
        if not query:
            continue
        rows, search_warnings = search_memory(
            query,
            limit=max(args.limit, 8),
            no_zvec=args.no_zvec,
            current_project=project_scope_for_file(
                entry.path,
                getattr(args, "current_project", ""),
            ),
            read_only=bool(getattr(args, "dry_run", False)),
        )
        warnings.extend(search_warnings)
        source_text = query
        candidates: list[dict[str, Any]] = []
        for row in rows:
            if row.get("path") == str(entry.path) or row.get("rel_path") == relative_to_vault(entry.path):
                continue
            if str(row.get("rel_path") or "") in declared_relations:
                continue
            if str(row.get("memory_type") or "").lower() in NONFACT_RECONCILE_TYPES:
                continue
            comparison = " ".join(
                str(row.get(key, ""))
                for key in ("title", "rel_path", "summary", "hit")
            )
            similarity = jaccard(source_text, comparison)
            row_coverage = coverage(source_text, comparison)
            distance = semantic_distance(row)
            raw_distance = raw_semantic_distance(row)
            semantic_duplicate = raw_distance is not None and raw_distance <= args.semantic_merge_threshold
            if similarity >= args.merge_threshold or row_coverage >= args.merge_coverage_threshold or semantic_duplicate:
                candidates.append(
                    {
                        "rel_path": row.get("rel_path", ""),
                        "title": row.get("title", ""),
                        "similarity": round(similarity, 4),
                        "coverage": round(row_coverage, 4),
                        "semantic_distance": round(distance, 4) if distance is not None else None,
                        "raw_semantic_distance": round(raw_distance, 4) if raw_distance is not None else None,
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
    command = [PYTHON, str(CHECK_SCRIPT), "--json"]
    for path in files:
        command.extend(["--changed-file", str(path)])
    result = run_command(command, timeout=180)
    try:
        payload = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError:
        result["detail"] = "check_returned_non_json"
        return result
    result["check_payload"] = payload
    result["advisories"] = payload.get("advisories", []) if isinstance(payload, dict) else []
    result["detail"] = str(payload.get("status", "")) if isinstance(payload, dict) else ""
    return result


def run_index(args: argparse.Namespace) -> dict[str, Any]:
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    return run_command([PYTHON, str(INDEX_SCRIPT), "--init", "--scan", "--report"], timeout=180)


def run_zvec(files: list[Path], args: argparse.Namespace) -> dict[str, Any]:
    if not SEMANTIC_ENABLED:
        return {"ok": True, "skipped": True, "detail": "semantic_retrieval_disabled"}
    if args.skip_zvec:
        return {"ok": True, "skipped": True, "detail": "skip_zvec"}
    if args.dry_run:
        return {"ok": True, "skipped": True, "detail": "dry_run"}
    command = [ZVEC_PYTHON, str(ZVEC_SCRIPT), "--prune", "--json"]
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


def _hash_object_bytes(data: bytes) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "hash-object", "-w", "--stdin"],
            input=data,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    object_id = completed.stdout.decode("ascii", errors="ignore").strip().lower()
    return completed.returncode == 0 and bool(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id)), object_id


def bind_checked_file_hashes(files: list[Path]) -> tuple[dict[Path, str], dict[str, str]]:
    """Bind each closeout file to raw and canonical hashes from one read."""

    bound: dict[Path, str] = {}
    canonical_bound: dict[str, str] = {}
    for raw_path in files:
        candidate = raw_path.expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if candidate.is_symlink():
            raise OSError(f"symlink target rejected: {candidate}")
        path = candidate.resolve()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError(f"not a regular file: {path}")
            digest = hashlib.sha256()
            payload = bytearray()
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                payload.extend(block)
        finally:
            os.close(descriptor)
        bound[path] = digest.hexdigest()
        canonical_bound[os.path.normcase(str(path))] = write_intent.content_hashes(
            bytes(payload)
        ).canonical_sha256
    return bound, canonical_bound


def _snapshot_commit_files(
    files: list[Path],
    expected_raw_sha256: dict[Path, str],
) -> tuple[list[CommitSnapshot], dict[str, Any] | None]:
    expected = {path.expanduser().resolve(): digest for path, digest in expected_raw_sha256.items()}
    snapshots: list[CommitSnapshot] = []
    seen: set[str] = set()
    for raw_path in files:
        candidate = raw_path.expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        if candidate.is_symlink():
            return [], {"ok": False, "stage": "snapshot", "detail": "symlink_target_rejected"}
        path = candidate.resolve()
        if not path.exists():
            continue
        try:
            repo_path = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            continue
        if repo_path in seen:
            continue
        seen.add(repo_path)
        try:
            data = path.read_bytes()
            executable = bool(path.stat().st_mode & 0o100)
        except OSError:
            return [], {"ok": False, "stage": "snapshot", "detail": "file_read_failed", "file": repo_path}
        raw_sha256 = hashlib.sha256(data).hexdigest()
        expected_digest = str(expected.get(path, "")).strip().lower()
        if expected_digest and raw_sha256 != expected_digest:
            return [], {
                "ok": False,
                "stage": "validated_snapshot_verify",
                "detail": "CONTENT_CHANGED_AFTER_CHECK",
                "file": repo_path,
            }
        object_ok, blob_oid = _hash_object_bytes(data)
        if not object_ok:
            return [], {"ok": False, "stage": "hash_object", "detail": "git_blob_write_failed", "file": repo_path}
        snapshots.append(
            CommitSnapshot(
                path=path,
                repo_path=repo_path,
                raw_sha256=raw_sha256,
                blob_oid=blob_oid,
                mode="100755" if executable else "100644",
            )
        )
    return snapshots, None


def _sync_real_index(snapshots: list[CommitSnapshot]) -> dict[str, Any]:
    for snapshot in snapshots:
        result = run_command(
            [
                "git", "-C", str(REPO_ROOT), "update-index", "--add", "--cacheinfo",
                snapshot.mode, snapshot.blob_oid, snapshot.repo_path,
            ],
            timeout=60,
        )
        if not result["ok"]:
            return {"ok": False, "stage": "index_sync", "detail": result, "file": snapshot.repo_path}
    return {"ok": True}


def _build_isolated_commit(
    snapshots: list[CommitSnapshot],
    *,
    expected_head: str,
    message: str,
) -> dict[str, Any]:
    transaction_dir = CONFIG_ROOT / "state"
    transaction_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if POSIX_PERMISSION_MODEL:
        try:
            transaction_dir.chmod(0o700)
        except OSError:
            return {"ok": False, "stage": "transaction_index", "detail": "transaction_directory_permission_failed"}
    index_path = transaction_dir / "closeout-transaction.index"
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(index_path)
    read_tree = run_command(
        ["git", "-C", str(REPO_ROOT), "read-tree", "--reset", expected_head],
        timeout=60,
        env=env,
    )
    if not read_tree["ok"]:
        return {"ok": False, "stage": "read_tree", "detail": read_tree}
    if POSIX_PERMISSION_MODEL:
        try:
            index_path.chmod(0o600)
        except OSError:
            return {"ok": False, "stage": "transaction_index", "detail": "transaction_index_permission_failed"}
    for snapshot in snapshots:
        update = run_command(
            [
                "git", "-C", str(REPO_ROOT), "update-index", "--add", "--cacheinfo",
                snapshot.mode, snapshot.blob_oid, snapshot.repo_path,
            ],
            timeout=60,
            env=env,
        )
        if not update["ok"]:
            return {"ok": False, "stage": "isolated_index", "detail": update, "file": snapshot.repo_path}
    tree_result = run_command(["git", "-C", str(REPO_ROOT), "write-tree"], timeout=60, env=env)
    if not tree_result["ok"]:
        return {"ok": False, "stage": "write_tree", "detail": tree_result}
    tree_oid = str(tree_result["stdout"]).strip().lower()
    head_tree = run_command(
        ["git", "-C", str(REPO_ROOT), "rev-parse", f"{expected_head}^{{tree}}"],
        timeout=30,
    )
    if not head_tree["ok"]:
        return {"ok": False, "stage": "head_tree", "detail": head_tree}
    if tree_oid == str(head_tree["stdout"]).strip().lower():
        sync = _sync_real_index(snapshots)
        return sync if not sync["ok"] else {"ok": True, "skipped": True, "detail": "nothing_staged"}

    commit_result = run_command(
        ["git", "-C", str(REPO_ROOT), "commit-tree", tree_oid, "-p", expected_head, "-m", message],
        timeout=120,
    )
    if not commit_result["ok"]:
        return {"ok": False, "stage": "commit_tree", "detail": commit_result}
    commit_oid = str(commit_result["stdout"]).strip().lower()
    update_ref = run_command(
        ["git", "-C", str(REPO_ROOT), "update-ref", "-m", "agent-memory closeout", "HEAD", commit_oid, expected_head],
        timeout=60,
    )
    if not update_ref["ok"]:
        return {"ok": False, "stage": "head_cas", "detail": "GIT_HEAD_CHANGED"}
    sync = _sync_real_index(snapshots)
    if not sync["ok"]:
        sync["commit"] = commit_oid
        return sync
    return {
        "ok": True,
        "skipped": False,
        "commit": commit_oid,
        "files": [snapshot.repo_path for snapshot in snapshots],
        "snapshot_sha256": {snapshot.repo_path: snapshot.raw_sha256 for snapshot in snapshots},
    }


def commit_files(
    files: list[Path],
    args: argparse.Namespace,
    *,
    expected_raw_sha256: dict[Path, str] | None = None,
    expected_head: str = "",
) -> dict[str, Any]:
    if not args.commit or args.dry_run:
        return {"ok": True, "skipped": True, "detail": "commit_not_requested"}
    snapshots, snapshot_error = _snapshot_commit_files(files, expected_raw_sha256 or {})
    if snapshot_error is not None:
        return snapshot_error
    if not snapshots:
        return {"ok": True, "skipped": True, "detail": "no_existing_files_to_commit"}
    if not expected_head:
        head_result = run_command(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], timeout=30)
        if not head_result["ok"]:
            return {"ok": False, "stage": "head", "detail": head_result}
        expected_head = str(head_result["stdout"]).strip()
    message = args.message or f"memory closeout[{args.actor}]: {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    return _build_isolated_commit(snapshots, expected_head=expected_head, message=message)


def append_log(payload: dict[str, Any]) -> None:
    secure_append_text(LOG_PATH, json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def privacy_safe_log_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip ephemeral scoped diffs before writing the durable JSONL audit log."""
    copied = json.loads(json.dumps(payload, ensure_ascii=False))
    validations = copied.get("write_intent_validations", [])
    if isinstance(validations, list):
        for validation in validations:
            if not isinstance(validation, dict):
                continue
            scoped_diff = validation.pop("scoped_diff", None)
            if isinstance(scoped_diff, str):
                validation["scoped_diff_sha256"] = hashlib.sha256(scoped_diff.encode("utf-8")).hexdigest()
                validation["scoped_diff_line_count"] = len(scoped_diff.splitlines())
                validation["scoped_diff_char_count"] = len(scoped_diff)
            mismatch = validation.get("mismatch")
            if isinstance(mismatch, dict):
                diff_text = mismatch.pop("diff", None)
                if isinstance(diff_text, str):
                    mismatch["diff_sha256"] = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
                    mismatch["diff_line_count"] = len(diff_text.splitlines())
                    mismatch["diff_char_count"] = len(diff_text)
    return copied


def unobserved_history_entries(entries: list[GitEntry]) -> list[GitEntry]:
    if not entries or not STATE_DB.exists():
        return entries
    try:
        with secure_sqlite_connect(
            STATE_DB,
            timeout=5,
            create=False,
            read_only=True,
            pragmas=("PRAGMA busy_timeout=5000",),
        ) as conn:
            rows = conn.execute("SELECT path, sha256 FROM memory_file_observations").fetchall()
            deletion_rows: list[tuple[Any, ...]] = []
            try:
                deletion_rows = conn.execute(
                    """
                    SELECT path, sentinel, actor, user_authorized,
                           deletion_commit, parent_commit, prior_sha256,
                           trash_sha256, trash_path_sha256,
                           evidence_ref_sha256, evidence_ref_length
                    FROM memory_deletion_observations
                    """
                ).fetchall()
            except sqlite3.Error:
                # Older state databases legitimately predate deletion observations.
                deletion_rows = []
    except (OSError, sqlite3.Error):
        return entries
    observed = {str(Path(str(path)).resolve()): str(digest) for path, digest in rows}
    deletion_audits: dict[tuple[str, str], tuple[str, str]] = {}
    for row in deletion_rows:
        (
            path,
            sentinel,
            actor,
            user_authorized,
            commit,
            parent_commit,
            prior_sha256,
            trash_sha256,
            trash_path_sha256,
            evidence_ref_sha256,
            evidence_ref_length,
        ) = row
        parsed = parse_deleted_observation(str(sentinel))
        try:
            authorized = int(user_authorized) == 1
            evidence_length = int(evidence_ref_length)
        except (TypeError, ValueError):
            continue
        if (
            parsed is None
            or str(actor) != "human"
            or not authorized
            or parsed != (str(commit), str(prior_sha256))
            or str(trash_sha256) != str(prior_sha256)
            or re.fullmatch(r"[0-9a-f]{40}", str(parent_commit)) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(trash_path_sha256)) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(evidence_ref_sha256)) is None
            or not 0 < evidence_length <= 4096
        ):
            continue
        deletion_audits[(str(Path(str(path)).resolve()), str(sentinel))] = parsed
    pending: list[GitEntry] = []
    for entry in entries:
        resolved_path = str(entry.path.resolve())
        try:
            digest = hashlib.sha256(entry.path.read_bytes()).hexdigest()
        except OSError:
            sentinel = observed.get(resolved_path, "")
            parsed = parse_deleted_observation(sentinel)
            audit = deletion_audits.get((resolved_path, sentinel))
            if entry.is_deleted and parsed is not None and audit == parsed:
                deletion_commit, _prior_sha256 = parsed
                latest = run_command(
                    [
                        "git",
                        "-C",
                        str(REPO_ROOT),
                        "log",
                        "-1",
                        "--format=%H",
                        "HEAD",
                        "--",
                        entry.repo_path,
                    ],
                    timeout=30,
                )
                latest_commit = str(latest.get("stdout", "")).strip().lower()
                if latest.get("ok") and latest_commit == deletion_commit:
                    continue
            pending.append(entry)
            continue
        if observed.get(resolved_path) != digest:
            pending.append(entry)
    return pending


def short_step(step: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": bool(step.get("ok")),
        "skipped": bool(step.get("skipped", False)),
        "returncode": step.get("returncode"),
        "detail": step.get("detail", ""),
        "duration_ms": step.get("duration_ms"),
        "advisory_count": len(step.get("advisories", [])) if isinstance(step.get("advisories"), list) else 0,
        "stderr": str(step.get("stderr", "")).strip()[:500],
    }


def run_closeout(args: argparse.Namespace) -> dict[str, Any]:
    warnings: list[str] = []
    info: list[str] = []
    git_entries, git_warnings = git_status_entries()
    warnings.extend(git_warnings)
    git_head_before, head_warnings = current_git_head()
    warnings.extend(head_warnings)
    previous_observed_head = last_observed_git_head()
    history_entries, history_warnings = git_history_entries(previous_observed_head, git_head_before)
    warnings.extend(history_warnings)
    pending_history_entries = unobserved_history_entries(history_entries)
    if pending_history_entries:
        info.append(
            f"recovered {len(pending_history_entries)} unobserved memory file changes "
            "from Git history after an external/automatic commit"
        )
    observed_history_count = len(history_entries) - len(pending_history_entries)
    if observed_history_count:
        info.append(f"ignored {observed_history_count} historical memory files with matching closeout observations")
    explicit, explicit_warnings = explicit_entries(args.changed_file)
    warnings.extend(explicit_warnings)

    by_path: dict[Path, GitEntry] = {entry.path: entry for entry in pending_history_entries}
    for entry in git_entries:
        by_path[entry.path] = entry
    for entry in explicit:
        by_path[entry.path] = entry
    discovered_entries = list(by_path.values())
    session_claim_rows = (
        active_claim_rows(
            args.session_id,
            args.actor,
            read_only=args.dry_run,
            max_age_hours=24,
        )
        if args.session_id
        else []
    )
    claim_rows = session_claim_rows if args.claimed_only else []
    claimed_paths = {Path(row["path"]).resolve() for row in claim_rows}
    excluded_entries: list[GitEntry] = []
    truly_unclaimed_entries: list[GitEntry] = []
    other_session_entries: list[GitEntry] = []
    ownership_error = ""
    if args.claimed_only:
        active_rows = all_active_claim_rows(max_age_hours=24, read_only=args.dry_run)
        all_claimed_paths = {Path(row["path"]).resolve() for row in active_rows}
        excluded_entries = [entry for entry in discovered_entries if entry.path not in claimed_paths]
        truly_unclaimed_entries = [
            entry for entry in excluded_entries if entry.path not in all_claimed_paths
        ]
        other_session_entries = [
            entry for entry in excluded_entries if entry.path in all_claimed_paths
        ]
        if not args.session_id:
            ownership_error = "claimed-only closeout requires --session-id"
        elif truly_unclaimed_entries:
            ownership_error = (
                f"no active memory claims cover {len(truly_unclaimed_entries)} changed file(s); "
                "claim each changed file with "
                f"memoryctl --actor {args.actor} claim --file <path>"
            )
        selected = {entry.path: entry for entry in discovered_entries if entry.path in claimed_paths}
        for path in claimed_paths:
            try:
                repo_path = path.relative_to(REPO_ROOT).as_posix()
            except ValueError:
                continue
            selected.setdefault(
                path,
                GitEntry(status="M" if path.exists() else "D", repo_path=repo_path, path=path),
            )
        all_entries = list(selected.values())
        if other_session_entries:
            info.append(f"excluded {len(other_session_entries)} files owned by other active sessions")
        if truly_unclaimed_entries:
            info.append(f"found {len(truly_unclaimed_entries)} files with no active session claim")
    else:
        all_entries = discovered_entries

    deleted_entries = [entry for entry in all_entries if entry.is_deleted]
    for entry in deleted_entries:
        warnings.append(f"deleted memory file not staged by closeout: {entry.repo_path}")

    process_entries = [
        entry
        for entry in all_entries
        if entry.exists and entry.is_memory_markdown and not entry.is_deleted
    ]
    process_files = [entry.path for entry in process_entries]

    claim_intent_ids = sorted(
        {
            str(row.get("intent_id", "")).strip()
            for row in session_claim_rows
            if str(row.get("intent_id", "")).strip()
        }
    )
    intent_gate: dict[str, Any] = {
        "ok": True,
        "mode": write_intent.ENFORCEMENT_MODE,
        "blocking": False,
        "matched": [],
        "violations": [],
    }
    intent_validations: list[dict[str, Any]] = []
    intent_error = ""
    try:
        intent_gate = write_intent.enforce_protected_changes(
            [entry.path for entry in process_entries],
            actor=args.actor,
            raw_session_id=args.session_id,
            intent_ids=claim_intent_ids,
            read_only=args.dry_run,
        )
        protected_deletions: list[str] = []
        for entry in deleted_entries:
            try:
                if write_intent.is_protected_target(entry.path):
                    protected_deletions.append(entry.repo_path)
            except write_intent.IntentError:
                continue
        if protected_deletions:
            violations = intent_gate.setdefault("violations", [])
            for path in protected_deletions:
                violations.append({"path": path, "reason_code": "PROTECTED_DELETE_FORBIDDEN"})
            intent_gate["blocking"] = write_intent.ENFORCEMENT_MODE == "enforce"
            intent_gate["ok"] = not bool(intent_gate["blocking"])
            warnings.append("protected memory deletion is never staged automatically")
        if intent_gate.get("violations") and intent_gate.get("mode") == "advisory":
            warnings.append("write-intent advisory: protected changes lack a matching bound intent")
        if not intent_gate.get("ok"):
            violations = intent_gate.get("violations", [])
            first_reason = (
                str(violations[0].get("reason_code", ""))
                if isinstance(violations, list) and violations and isinstance(violations[0], dict)
                else "PROTECTED_WRITE_REJECTED"
            )
            intent_error = first_reason or "PROTECTED_WRITE_REJECTED"
    except (write_intent.IntentError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        intent_error = str(getattr(exc, "reason_code", "INTENT_GATE_FAILED"))

    if not intent_error:
        entry_paths = {entry.path.resolve() for entry in all_entries}
        matched_intent_ids = {
            str(item.get("intent_id", ""))
            for item in intent_gate.get("matched", [])
            if isinstance(item, dict) and str(item.get("intent_id", "")).strip()
        }
        claim_path_by_intent = {
            str(row.get("intent_id", "")).strip(): Path(str(row.get("path", ""))).expanduser().resolve()
            for row in session_claim_rows
            if str(row.get("intent_id", "")).strip()
        }
        if any(intent_id not in claim_path_by_intent for intent_id in matched_intent_ids):
            intent_error = "PROTECTED_WRITE_WITHOUT_MATCHING_CLAIM"
        validation_intent_ids = sorted(
            intent_id
            for intent_id, claim_path in claim_path_by_intent.items()
            if claim_path in entry_paths
        )
        if intent_error:
            validation_intent_ids = []
        for intent_id in validation_intent_ids:
            claim_path = claim_path_by_intent.get(intent_id)
            if claim_path is None:
                continue
            try:
                validation = write_intent.validate_closeout(
                    intent_id,
                    actor=args.actor,
                    raw_session_id=args.session_id,
                    target=claim_path,
                    mutate=not args.dry_run,
                )
            except (write_intent.IntentError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
                validation = {
                    "ok": False,
                    "intent_id": intent_id,
                    "reason_code": str(getattr(exc, "reason_code", "INTENT_VALIDATE_FAILED")),
                }
            intent_validations.append(validation)
            if not validation.get("ok") and not intent_error:
                intent_error = str(validation.get("reason_code") or "INTENT_VALIDATE_FAILED")

    preflight_error = ownership_error or intent_error
    checked_commit_hashes: dict[Path, str] = {}
    checked_canonical_hashes: dict[str, str] = {}
    if process_files and not preflight_error:
        try:
            # Bind all ordinary and protected files before validation checks;
            # the isolated snapshot below must still contain these bytes.
            checked_commit_hashes, checked_canonical_hashes = bind_checked_file_hashes(
                process_files
            )
        except (OSError, write_intent.IntentError):
            preflight_error = "CHECK_INPUT_BIND_FAILED"

    if not preflight_error:
        for validation in intent_validations:
            if not validation.get("ok") or validation.get("completed"):
                continue
            intent_id = str(validation.get("intent_id", ""))
            claim_path = claim_path_by_intent.get(intent_id)
            final_canonical = str(validation.get("final_canonical_sha256", "")).strip().lower()
            if claim_path is None or not final_canonical:
                continue
            checked_key = os.path.normcase(str(claim_path.resolve()))
            if checked_canonical_hashes.get(checked_key) != final_canonical:
                preflight_error = "VALIDATED_CONTENT_CHANGED"
                break

    if args.dry_run:
        info.append("dry_run: no index refresh, zvec refresh, or commit will be written")
    if git_entries:
        info.append(
            "git reports dirty Agent Memory files; if some are historical, review dry-run output before committing"
        )

    check_step = run_check(process_files, args) if process_files and not preflight_error else {
        "ok": not bool(preflight_error),
        "skipped": True,
        "detail": preflight_error or "no_changed_files",
    }
    advisories = list(check_step.get("advisories", [])) if isinstance(check_step.get("advisories"), list) else []
    reconcile_findings, reconcile_warnings = (
        postwrite_reconcile(process_entries, args) if not preflight_error else ([], [])
    )
    warnings.extend(reconcile_warnings)
    index_step = run_index(args) if process_files and not preflight_error else {"ok": not bool(preflight_error), "skipped": True, "detail": preflight_error or "no_changed_files"}
    zvec_step = run_zvec(process_files, args) if process_files and not preflight_error else {"ok": not bool(preflight_error), "skipped": True, "detail": preflight_error or "no_changed_files"}
    agent_step = run_agent_evolution(process_files, args) if process_files and not preflight_error else {"ok": not bool(preflight_error), "skipped": True, "detail": preflight_error or "no_changed_files"}
    audit_step = run_audit_autorun(args) if not preflight_error else {"ok": False, "skipped": True, "detail": preflight_error}
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
    elif not audit_step.get("ok") and not audit_step.get("skipped"):
        detail = str(audit_step.get("stderr", "")).strip() or str(audit_step.get("detail", "")).strip()
        info.append(f"audit autorun failed: {detail[:300]}")

    blocking_reconcile = bool(reconcile_findings)
    step_failed = bool(preflight_error) or not all(
        bool(step.get("ok"))
        for step in (check_step, index_step, zvec_step, agent_step)
    )
    status = "ok"
    if step_failed:
        status = "error"
    elif blocking_reconcile or warnings:
        status = "warning"

    commit_step: dict[str, Any]
    early_commit_paths = {
        claim_path_by_intent[str(validation.get("intent_id", ""))].resolve()
        for validation in intent_validations
        if validation.get("ok")
        and validation.get("early_commit")
        and str(validation.get("intent_id", "")) in claim_path_by_intent
    }
    commit_process_files = [
        path for path in process_files if path.resolve() not in early_commit_paths
    ]
    if status == "error":
        commit_step = {"ok": False, "skipped": True, "detail": "skipped_due_to_error"}
    elif blocking_reconcile and not args.commit_warnings:
        commit_step = {"ok": True, "skipped": True, "detail": "skipped_due_to_merge_required"}
    elif status == "warning" and not args.commit_warnings:
        commit_step = {"ok": True, "skipped": True, "detail": "skipped_due_to_warning"}
    else:
        commit_step = commit_files(
            commit_process_files,
            args,
            expected_raw_sha256=checked_commit_hashes,
            expected_head=git_head_before,
        )
        if not commit_step.get("ok"):
            status = "error"

    intent_receipts: list[dict[str, Any]] = []
    intent_step: dict[str, Any] = {
        "ok": not bool(intent_error),
        "skipped": not bool(intent_validations),
        "detail": intent_error or ("no_bound_intents" if not intent_validations else "validated"),
    }
    if status == "ok" and not args.dry_run and intent_validations:
        for validation in intent_validations:
            if not validation.get("ok"):
                continue
            durable_commit = str(
                validation.get("proposal_commit")
                if validation.get("early_commit")
                else commit_step.get("commit")
            ).strip()
            if not durable_commit:
                intent_error = "PROTECTED_WRITE_NOT_DURABLE"
                intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                status = "error"
                break
            try:
                receipt = write_intent.finalize_receipt(
                    str(validation.get("intent_id", "")),
                    actor=args.actor,
                    raw_session_id=args.session_id,
                    outcome="completed",
                    git_commit=durable_commit,
                    detail_code="EARLY_COMMIT_RECOVERED" if validation.get("early_commit") else "CLOSEOUT_COMMIT",
                )
            except (write_intent.IntentError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
                intent_error = str(getattr(exc, "reason_code", "INTENT_RECEIPT_FAILED"))
                intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                status = "error"
                break
            intent_receipts.append(receipt)
            if str(receipt.get("outcome", "")) != "completed":
                intent_error = "RECEIPT_OUTCOME_CONFLICT"
                intent_step = {"ok": False, "skipped": False, "detail": intent_error}
                status = "error"
                break
        else:
            intent_step = {
                "ok": True,
                "skipped": False,
                "detail": f"validated={len(intent_validations)} receipts={len(intent_receipts)}",
            }

    claim_step: dict[str, Any] = {"ok": True, "skipped": True, "detail": "ownership_not_enabled"}
    observation_step: dict[str, Any] = {"ok": True, "skipped": True, "detail": "not_completed"}
    if status == "ok" and not args.dry_run and commit_step.get("ok"):
        try:
            observed = record_file_observations(args.session_id, args.actor, process_files)
            observation_step = {"ok": True, "skipped": False, "detail": f"recorded={observed}"}
        except (OSError, sqlite3.Error, ValueError) as exc:
            observation_step = {"ok": False, "skipped": False, "detail": str(exc)}
            status = "error"
    if args.claimed_only:
        claim_step = {"ok": True, "skipped": True, "detail": "claims_retained"}
        if status == "ok" and not args.dry_run and commit_step.get("ok"):
            completed = complete_claim_paths(args.session_id, args.actor, process_files)
            claim_step = {"ok": True, "skipped": False, "detail": f"completed={completed}"}

    git_head_after, after_warnings = current_git_head()
    warnings.extend(after_warnings)
    dirty_paths = {entry.path for entry in git_entries}
    unclaimed_history = unobserved_history_entries(
        [entry for entry in pending_history_entries if entry.path in {item.path for item in excluded_entries}]
    )
    can_advance_baseline = (
        status == "ok" and not step_failed and intent_step.get("ok")
        and observation_step.get("ok") and not blocking_reconcile
        and not deleted_entries and not unclaimed_history and bool(git_head_before)
        and (not dirty_paths or bool(commit_step.get("commit")) or commit_step.get("detail") == "nothing_staged")
    )
    would_observe_through = (
        str(commit_step.get("commit")) if can_advance_baseline and commit_step.get("commit")
        else (git_head_before if can_advance_baseline else previous_observed_head)
    )
    git_observed_through = previous_observed_head if args.dry_run else would_observe_through

    payload = {
        "time": utc_now(),
        "run_id": uuid.uuid4().hex,
        "actor": args.actor,
        "trigger": args.trigger,
        "session_hash": session_hash(args.session_id),
        "ownership_mode": "claimed_only" if args.claimed_only else "global",
        "ownership_error": ownership_error,
        "intent_error": intent_error,
        "write_intent_gate": intent_gate,
        "write_intent_validations": intent_validations,
        "write_intent_receipts": intent_receipts,
        "cwd": str(Path.cwd()),
        "mode": "closeout",
        "git_previous_observed_head": previous_observed_head,
        "git_head_before": git_head_before,
        "git_head_after": git_head_after,
        "git_observed_through": git_observed_through,
        "git_would_observe_through": would_observe_through,
        "changed_files": [entry.repo_path for entry in all_entries],
        "claimed_files": sorted(row["rel_path"] for row in claim_rows),
        "unclaimed_files": sorted(entry.repo_path for entry in truly_unclaimed_entries),
        "other_session_files": sorted(entry.repo_path for entry in other_session_entries),
        "processed_files": [relative_to_vault(path) for path in process_files],
        "deleted_files_skipped": [entry.repo_path for entry in deleted_entries],
        "reconcile_findings": reconcile_findings,
        "info": info,
        "warnings": warnings,
        "advisories": advisories,
        "steps": {
            "check": short_step(check_step),
            "sqlite": short_step(index_step),
            "zvec": short_step(zvec_step),
            "agent_evolution": short_step(agent_step),
            "audit": short_step(audit_step),
            "commit": short_step(commit_step),
            "write_intents": short_step(intent_step),
            "observations": short_step(observation_step),
            "claims": short_step(claim_step),
        },
        "commit": commit_step.get("commit", "skipped"),
        "status": status,
    }
    if not args.dry_run:
        append_log(privacy_safe_log_payload(payload))
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
        description="Unified closeout for the local Agent Memory system."
    )
    parser.add_argument("--prewrite", help="Run reconcile before writing a new memory; does not modify files.")
    parser.add_argument("--create-intent", action="store_true", help="Create a content-bound write intent after safety and reconcile pass.")
    parser.add_argument("--target-file", default="", help="Canonical memory target for --create-intent.")
    parser.add_argument("--proposal-file", default="", help="UTF-8 proposal outside the vault for --create-intent.")
    parser.add_argument(
        "--source-class",
        choices=sorted(SOURCE_CLASSES),
        default="unknown",
        help="Origin class for the proposed memory. Unknown sources require confirmation.",
    )
    parser.add_argument(
        "--knowledge-kind",
        choices=sorted(KNOWLEDGE_KINDS),
        default="fact",
        help="Whether the proposal is a fact, preference, rule, inference, or hypothesis.",
    )
    parser.add_argument("--asserted-by", default="", help="Bounded identity label for who asserted the proposal.")
    parser.add_argument("--evidence-ref", default="", help="Evidence reference; only its hash is included in safety output.")
    parser.add_argument("--changed-file", action="append", default=[], help="Explicit changed memory file. Repeatable.")
    parser.add_argument("--limit", type=int, default=8, help="Search candidates for reconcile.")
    parser.add_argument(
        "--current-project",
        default="",
        help="Current project_id for prewrite and postwrite search boundaries.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--dry-run", action="store_true", help="Inspect only; do not refresh indexes, write logs, or commit.")
    parser.add_argument("--commit", action="store_true", help="After successful closeout, commit only processed memory files.")
    parser.add_argument("--commit-warnings", action="store_true", help="Allow commit when non-blocking warnings exist.")
    parser.add_argument("--message", default="", help="Custom scoped commit message.")
    parser.add_argument("--actor", default=os.environ.get("MEMORY_ACTOR", "codex"), help="Agent that initiated closeout.")
    parser.add_argument(
        "--trigger",
        default="manual",
        choices=("manual", "stop-hook", "session-end", "launchd", "migration", "test"),
        help="How this closeout run was triggered.",
    )
    parser.add_argument("--session-id", default="", help="Optional session id; only a one-way hash is logged.")
    parser.add_argument(
        "--claimed-only",
        action="store_true",
        help="Process only files actively claimed by this actor and session.",
    )
    parser.add_argument("--skip-zvec", action="store_true", help="Skip Zvec refresh.")
    parser.add_argument("--no-zvec", action="store_true", help="Skip Zvec during prewrite/postwrite reconcile search.")
    parser.add_argument("--zvec-timeout", type=int, default=240, help="Seconds before Zvec refresh times out.")
    parser.add_argument("--reconcile-all", action="store_true", help="Run postwrite reconcile on all changed files, not only new files.")
    parser.add_argument("--merge-threshold", type=float, default=0.42, help="Similarity threshold for MERGE_REQUIRED.")
    parser.add_argument("--merge-coverage-threshold", type=float, default=0.35, help="Coverage threshold for MERGE_REQUIRED.")
    parser.add_argument("--semantic-merge-threshold", type=float, default=0.32, help="Semantic distance threshold for postwrite MERGE_REQUIRED.")
    parser.add_argument("--lock-timeout", type=float, default=15.0, help="Seconds to wait for another closeout process.")
    parser.add_argument("--skip-audit", action="store_true", help="Skip the weekly audit piggyback check.")
    parser.add_argument("--audit-interval-days", type=int, default=7, help="Run audit from closeout when the last successful audit is older than this.")
    parser.add_argument("--audit-limit", type=int, default=50, help="Maximum audit findings stored by closeout piggyback.")
    parser.add_argument("--audit-stale-days", type=int, default=120, help="Forwarded stale threshold for closeout piggyback audit.")
    parser.add_argument("--audit-open-loop-threshold", type=int, default=4, help="Forwarded open-loop threshold for closeout piggyback audit.")
    parser.add_argument("--audit-timeout", type=int, default=180, help="Seconds before closeout piggyback audit times out.")
    args = parser.parse_args()
    args.actor = normalized_actor(args.actor)
    if args.actor == "yichen-content-studio":
        if args.session_id:
            parser.error("yichen-content-studio session id must be supplied through AGENT_MEMORY_SESSION_ID")
        args.session_id = os.environ.get("AGENT_MEMORY_SESSION_ID", "").strip()
    args.limit = max(args.limit, 1)
    args.audit_interval_days = max(args.audit_interval_days, 1)
    args.audit_limit = max(args.audit_limit, 1)
    args.audit_stale_days = max(args.audit_stale_days, 1)
    args.audit_open_loop_threshold = max(args.audit_open_loop_threshold, 1)
    if not SEMANTIC_ENABLED:
        args.no_zvec = True
        args.skip_zvec = True
    if args.prewrite:
        args.dry_run = True
    return args


def main() -> int:
    args = parse_args()
    if args.prewrite:
        payload = run_prewrite(args)
    else:
        try:
            with closeout_lock(args.lock_timeout):
                payload = run_closeout(args)
        except TimeoutError as exc:
            payload = {
                "time": utc_now(), "mode": "closeout", "status": "error",
                "warnings": [], "advisories": [], "error": str(exc), "steps": {},
            }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(payload)
    if payload.get("status") == "error":
        return 2
    if payload.get("status") == "warning":
        return 1
    if payload.get("status") == "blocked":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
