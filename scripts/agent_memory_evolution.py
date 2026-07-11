#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from agent_memory_env import env_value


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VAULT_ROOT = REPO_ROOT / "templates" / "vault"
VAULT_ROOT = Path(os.path.expandvars(env_value("ROOT", str(DEFAULT_VAULT_ROOT)))).expanduser().resolve()
AGENT_ROOT = VAULT_ROOT / "agent"
STATE_DB = Path(
    os.path.expandvars(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite"))
).expanduser().resolve()

CASE_CANDIDATE_DIR = AGENT_ROOT / "case-candidates"
CASE_DIR = AGENT_ROOT / "cases"
SKILL_CANDIDATE_DIR = AGENT_ROOT / "skill-candidates"


@dataclass
class AgentMemory:
    path: Path
    sha256: str
    memory_type: str
    status: str
    case_key: str
    task_type: str
    promotion_state: str
    reuse_count: int
    evidence_count: int
    risk_flags: list[str]
    last_seen: str
    title: str


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def slug_from_path(path: Path) -> str:
    stem = path.stem
    stem = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", stem)
    stem = re.sub(r"[^A-Za-z0-9\u4e00-\u9fff]+", "-", stem).strip("-")
    return stem or hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:12]


def parse_frontmatter(text: str) -> dict[str, object]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    data: dict[str, object] = {}
    current_key = ""
    for line in text[4:end].splitlines():
        if not line.strip():
            continue
        if line.startswith(("  - ", "- ")) and current_key:
            item = line.split("- ", 1)[1].strip()
            data.setdefault(current_key, [])
            if isinstance(data[current_key], list):
                data[current_key].append(item)
            continue
        if line.startswith(" ") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        current_key = key.strip()
        value = value.strip()
        data[current_key] = value if value else []
    return data


def as_int(value: object, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip() and value.strip() != "[]":
        return [value.strip()]
    return []


def as_text(value: object, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip().strip('"').strip("'")
    return text if text else default


def title_from_markdown(text: str, path: Path) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


def load_agent_memory(path: Path) -> AgentMemory | None:
    if path.name.startswith("_模板") or path.name == "README.md":
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    meta = parse_frontmatter(text)
    memory_type = as_text(meta.get("memory_type"))
    if memory_type not in {"agent_case_candidate", "agent_case", "skill_candidate"}:
        return None
    case_key = as_text(meta.get("case_key")) or slug_from_path(path)
    task_type = as_text(meta.get("task_type")) or case_key
    promotion_state = as_text(meta.get("promotion_state"))
    if not promotion_state:
        promotion_state = "candidate" if memory_type != "agent_case" else "active"
    return AgentMemory(
        path=path,
        sha256=sha256_text(text),
        memory_type=memory_type,
        status=as_text(meta.get("status")),
        case_key=case_key,
        task_type=task_type,
        promotion_state=promotion_state,
        reuse_count=as_int(meta.get("reuse_count"), 1),
        evidence_count=as_int(meta.get("evidence_count"), 1),
        risk_flags=as_list(meta.get("risk_flags")),
        last_seen=as_text(meta.get("last_seen")) or as_text(meta.get("verified_at")),
        title=title_from_markdown(text, path),
    )


def iter_agent_memories() -> list[AgentMemory]:
    memories: list[AgentMemory] = []
    for folder in (CASE_CANDIDATE_DIR, CASE_DIR, SKILL_CANDIDATE_DIR):
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.md")):
            memory = load_agent_memory(path)
            if memory:
                memories.append(memory)
    return memories


def connect() -> sqlite3.Connection:
    STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(STATE_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memory_files (
          path TEXT PRIMARY KEY,
          sha256 TEXT NOT NULL,
          memory_type TEXT NOT NULL,
          status TEXT,
          case_key TEXT,
          task_type TEXT,
          promotion_state TEXT,
          reuse_count INTEGER DEFAULT 0,
          evidence_count INTEGER DEFAULT 0,
          risk_flags TEXT DEFAULT '',
          last_seen TEXT,
          title TEXT,
          scanned_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_case_state (
          case_key TEXT PRIMARY KEY,
          task_type TEXT,
          candidate_count INTEGER DEFAULT 0,
          active_count INTEGER DEFAULT 0,
          skill_candidate_count INTEGER DEFAULT 0,
          total_reuse_count INTEGER DEFAULT 0,
          total_evidence_count INTEGER DEFAULT 0,
          risk_flags TEXT DEFAULT '',
          last_seen TEXT,
          recommendation TEXT DEFAULT 'none',
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reminders (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_key TEXT NOT NULL,
          kind TEXT NOT NULL,
          message TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open',
          created_at TEXT NOT NULL,
          resolved_at TEXT
        );
        """
    )
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("agent_evolution_schema_version", "1"))


def upsert_file(conn: sqlite3.Connection, memory: AgentMemory, scanned_at: str) -> None:
    conn.execute(
        """
        INSERT INTO memory_files (
          path, sha256, memory_type, status, case_key, task_type, promotion_state,
          reuse_count, evidence_count, risk_flags, last_seen, title, scanned_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
          sha256=excluded.sha256,
          memory_type=excluded.memory_type,
          status=excluded.status,
          case_key=excluded.case_key,
          task_type=excluded.task_type,
          promotion_state=excluded.promotion_state,
          reuse_count=excluded.reuse_count,
          evidence_count=excluded.evidence_count,
          risk_flags=excluded.risk_flags,
          last_seen=excluded.last_seen,
          title=excluded.title,
          scanned_at=excluded.scanned_at
        """,
        (
            str(memory.path),
            memory.sha256,
            memory.memory_type,
            memory.status,
            memory.case_key,
            memory.task_type,
            memory.promotion_state,
            memory.reuse_count,
            memory.evidence_count,
            ",".join(memory.risk_flags),
            memory.last_seen,
            memory.title,
            scanned_at,
        ),
    )


def recommendation_for(
    candidate_count: int,
    active_count: int,
    skill_count: int,
    total_reuse: int,
    total_evidence: int,
    risks: list[str],
) -> str:
    high_risk = any(risk.lower() in {"privacy", "secret", "destructive", "unsafe"} for risk in risks)
    if skill_count > 0:
        return "review_skill_candidate_with_user"
    if total_reuse >= 3 and total_evidence >= 2 and not high_risk:
        return "consider_skill_candidate"
    if active_count > 0:
        return "active_case"
    if candidate_count > 0:
        return "keep_case_candidate"
    return "none"


def aggregate(conn: sqlite3.Connection, memories: list[AgentMemory], scanned_at: str) -> None:
    conn.execute("DELETE FROM agent_case_state")
    by_key: dict[str, list[AgentMemory]] = {}
    for memory in memories:
        by_key.setdefault(memory.case_key, []).append(memory)

    for case_key, items in sorted(by_key.items()):
        candidate_count = sum(1 for item in items if item.memory_type == "agent_case_candidate")
        active_count = sum(1 for item in items if item.memory_type == "agent_case")
        skill_count = sum(1 for item in items if item.memory_type == "skill_candidate")
        total_reuse = sum(max(item.reuse_count, 0) for item in items)
        total_evidence = sum(max(item.evidence_count, 0) for item in items)
        risks = sorted({risk for item in items for risk in item.risk_flags if risk})
        task_type = next((item.task_type for item in items if item.task_type), case_key)
        last_seen = max((item.last_seen for item in items if item.last_seen), default="")
        recommendation = recommendation_for(candidate_count, active_count, skill_count, total_reuse, total_evidence, risks)

        conn.execute(
            """
            INSERT INTO agent_case_state (
              case_key, task_type, candidate_count, active_count, skill_candidate_count,
              total_reuse_count, total_evidence_count, risk_flags, last_seen,
              recommendation, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_key,
                task_type,
                candidate_count,
                active_count,
                skill_count,
                total_reuse,
                total_evidence,
                ",".join(risks),
                last_seen,
                recommendation,
                scanned_at,
            ),
        )

        if recommendation in {"review_skill_candidate_with_user", "consider_skill_candidate"}:
            existing = conn.execute(
                "SELECT COUNT(*) FROM reminders WHERE case_key=? AND kind='skill_review' AND status='open'",
                (case_key,),
            ).fetchone()[0]
            if not existing:
                conn.execute(
                    """
                    INSERT INTO reminders(case_key, kind, message, status, created_at)
                    VALUES (?, 'skill_review', ?, 'open', ?)
                    """,
                    (
                        case_key,
                        f"Review whether case_key={case_key} should become a formal skill.",
                        scanned_at,
                    ),
                )


def print_report(conn: sqlite3.Connection) -> None:
    total_files = conn.execute("SELECT COUNT(*) FROM memory_files").fetchone()[0]
    total_cases = conn.execute("SELECT COUNT(*) FROM agent_case_state").fetchone()[0]
    open_reminders = conn.execute("SELECT COUNT(*) FROM reminders WHERE status='open'").fetchone()[0]
    print(f"vault_root={VAULT_ROOT}")
    print(f"state_db={STATE_DB}")
    print(f"agent_memory_files={total_files}")
    print(f"agent_case_keys={total_cases}")
    print(f"open_reminders={open_reminders}")
    for row in conn.execute(
        """
        SELECT case_key, recommendation, total_reuse_count, total_evidence_count
        FROM agent_case_state
        ORDER BY recommendation DESC, total_reuse_count DESC, case_key
        LIMIT 10
        """
    ):
        case_key, recommendation, reuse_count, evidence_count = row
        print(
            f"case[{case_key}] recommendation={recommendation} "
            f"reuse_count={reuse_count} evidence_count={evidence_count}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Index Agent memory files in SQLite.")
    parser.add_argument("--init", action="store_true", help="Create or migrate the SQLite schema.")
    parser.add_argument("--scan", action="store_true", help="Scan agent case files and update state.")
    parser.add_argument("--report", action="store_true", help="Print current state summary.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not (args.init or args.scan or args.report):
        args.init = True
        args.scan = True
        args.report = True

    with connect() as conn:
        if args.init or args.scan:
            init_db(conn)
        if args.scan:
            scanned_at = utc_now()
            memories = iter_agent_memories()
            for memory in memories:
                upsert_file(conn, memory, scanned_at)
            aggregate(conn, memories, scanned_at)
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("agent_evolution_last_scan_at", scanned_at))
        if args.report or args.scan:
            print_report(conn)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
