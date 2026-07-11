#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from agent_memory_env import env_value


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VAULT_ROOT = REPO_ROOT / "templates" / "vault"
VAULT_ROOT = Path(os.path.expandvars(env_value("ROOT", str(DEFAULT_VAULT_ROOT)))).expanduser().resolve()
STATE_DB = Path(
    os.path.expandvars(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite"))
).expanduser().resolve()
DEFAULT_USER_ID = env_value("USER_ID", "demo-user")
DEFAULT_AGENT_ID = env_value("AGENT_ID", "shared")
DEFAULT_APP_ID = env_value("APP_ID", "agent-memory")
DEFAULT_LIMIT = 5


@dataclass
class MemoryDoc:
    path: Path
    rel_path: str
    sha256: str
    title: str
    memory_type: str
    track: str
    project_id: str
    app_id: str
    user_id: str
    agent_id: str
    agent_scope: str
    session_id: str
    status: str
    sensitivity: str
    verified_at: str
    verified_at_source: str
    review_after_days: int
    mtime: float
    size_bytes: int
    line_count: int
    summary: str
    next_hint: str
    stale_info: str
    has_open_loop: int
    open_loop_count: int
    keywords: str
    headings: str
    search_text: str
    indexed_at: str


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def as_text(value: object, default: str = "") -> str:
    if isinstance(value, list):
        text = ", ".join(str(item).strip() for item in value if str(item).strip())
        return text if text else default
    if value is None:
        return default
    text = str(value).strip().strip('"').strip("'")
    return text if text else default


def title_from_markdown(text: str, path: Path) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


def headings_from_markdown(text: str) -> str:
    headings: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
            if heading:
                headings.append(heading)
    return " | ".join(headings)


def compact_lines(lines: list[str], limit: int = 500) -> str:
    cleaned: list[str] = []
    for line in lines:
        item = line.strip()
        if not item or item.startswith("```"):
            continue
        item = re.sub(r"^[-*]\s*", "", item)
        cleaned.append(item)
    text = "；".join(cleaned)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def section_lines(text: str, heading_patterns: list[str]) -> list[str]:
    lines = text.splitlines()
    capture = False
    captured: list[str] = []
    for line in lines:
        if line.startswith("## "):
            heading = line[3:].strip()
            if any(pattern in heading for pattern in heading_patterns):
                capture = True
                continue
            if capture:
                break
        if capture:
            captured.append(line)
    return captured


def extract_summary(text: str) -> str:
    lines = section_lines(text, ["当前有效摘要"])
    if lines:
        return compact_lines(lines, 700)
    body = [line for line in text.splitlines() if line.strip() and not line.startswith("---")]
    return compact_lines(body[:12], 500)


def extract_verified_at(
    text: str,
    meta: dict[str, object],
    memory_type: str,
    status: str,
) -> tuple[str, str]:
    frontmatter_value = as_text(meta.get("verified_at"))
    if frontmatter_value:
        return frontmatter_value, "frontmatter"
    verification_mode = as_text(meta.get("verification_mode")).lower()
    if verification_mode in {"structural", "snapshot", "needs_review"}:
        return "", verification_mode
    match = re.search(r"最近验证[:：]\s*(\d{4}-\d{2}-\d{2})", text)
    if match:
        return match.group(1), "summary"
    summary_dates = re.findall(r"\b(20\d{2}-\d{2}-\d{2})\b", extract_summary(text))
    if summary_dates:
        return max(summary_dates), "document_date"
    if status in {"archived", "outdated", "deprecated", "stale"}:
        return "", "snapshot"
    if memory_type in {"routing", "directory_index", "template"}:
        return "", "structural"
    return "", "needs_review"


def infer_review_after_days(path: Path, title: str, memory_type: str, status: str, meta: dict[str, object]) -> int:
    explicit = as_text(meta.get("review_after_days"))
    if explicit:
        try:
            return max(1, min(int(explicit), 3650))
        except ValueError:
            pass
    haystack = f"{path.as_posix()} {title}"
    if status == "candidate" or memory_type in {"agent_case_candidate", "skill_candidate", "open_loop"}:
        return 30
    if "产品调研" in haystack or "竞品调研" in haystack:
        return 30
    return {
        "project": 90,
        "workflow": 180,
        "user_profile": 365,
        "decision": 365,
        "routing": 365,
        "directory_index": 365,
        "template": 365,
    }.get(memory_type, 180)


def infer_from_path(path: Path, meta: dict[str, object]) -> tuple[str, str, str, str]:
    rel = path.relative_to(VAULT_ROOT)
    parts = rel.parts
    name = path.stem

    if path.name == "README.md":
        parent = Path(*parts[:-1]).as_posix() if len(parts) > 1 else name
        default_track = parts[0] if len(parts) > 1 else "routing"
        return "directory_index", as_text(meta.get("track"), default_track), as_text(meta.get("project_id"), parent), as_text(meta.get("status"), "active")
    if path.name.startswith("_模板"):
        return "template", as_text(meta.get("track"), parts[0] if parts else "template"), as_text(meta.get("project_id"), name), as_text(meta.get("status"), "active")

    memory_type = as_text(meta.get("memory_type"))
    track = as_text(meta.get("track"))
    project_id = as_text(meta.get("project_id"))
    status = as_text(meta.get("status"))

    if memory_type and track:
        return memory_type, track, project_id or name, status or "active"

    if len(parts) == 1:
        return memory_type or "routing", track or "routing", project_id or name, status or "active"

    top = parts[0]
    if top == "用户记忆":
        return "user_profile", "user", project_id or "global", status or "active"
    if top == "项目":
        return "project", "project", project_id or name, status or "active"
    if top == "工作流":
        return "workflow", "workflow", project_id or name, status or "active"
    if top == "决策":
        return "decision", "decision", project_id or name, status or "active"
    if top == "agent":
        if len(parts) > 1 and parts[1] == "case-candidates":
            return "agent_case_candidate", "agent", project_id or name, status or "candidate"
        if len(parts) > 1 and parts[1] == "cases":
            return "agent_case", "agent", project_id or name, status or "active"
        if len(parts) > 1 and parts[1] == "skill-candidates":
            return "skill_candidate", "agent", project_id or name, status or "candidate"
        if path.name == "open-loops.md":
            return "open_loop", "agent", project_id or "open-loops", status or "active"
        return "agent_note", "agent", project_id or name, status or "active"
    return memory_type or "note", track or "misc", project_id or name, status or "active"


def extract_open_loops(path: Path, title: str, rel_path: str, text: str, indexed_at: str) -> list[tuple[str, str, str, str, str, str]]:
    records: list[tuple[str, str, str, str, str, str]] = []
    sections = [
        ("next_hint", ["下次优先看"]),
        ("open_loop", ["未闭环", "待办", "TODO"]),
        ("risk", ["风险"]),
    ]
    for kind, patterns in sections:
        for raw in section_lines(text, patterns):
            item = raw.strip()
            if not item.startswith(("-", "*")):
                continue
            item = re.sub(r"^[-*]\s*", "", item).strip()
            if item and item != "暂无。":
                records.append((str(path), rel_path, title, kind, item[:500], indexed_at))
    return records


def load_doc(path: Path, indexed_at: str) -> tuple[MemoryDoc, list[tuple[str, str, str, str, str, str]]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    meta = parse_frontmatter(text)
    stat = path.stat()
    rel_path = path.relative_to(VAULT_ROOT).as_posix()
    title = title_from_markdown(text, path)
    memory_type, track, project_id, status = infer_from_path(path, meta)
    verified_at, verified_at_source = extract_verified_at(text, meta, memory_type, status)
    summary = extract_summary(text)
    next_hint = compact_lines(section_lines(text, ["下次优先看"]), 500)
    stale_info = compact_lines(section_lines(text, ["已过时信息"]), 500)
    headings = headings_from_markdown(text)
    keywords = as_text(meta.get("keywords"))
    open_loops = extract_open_loops(path, title, rel_path, text, indexed_at)
    return (
        MemoryDoc(
            path=path,
            rel_path=rel_path,
            sha256=sha256_text(text),
            title=title,
            memory_type=memory_type,
            track=track,
            project_id=project_id,
            app_id=as_text(meta.get("app_id"), DEFAULT_APP_ID),
            user_id=as_text(meta.get("user_id"), DEFAULT_USER_ID),
            agent_id=as_text(meta.get("agent_id"), DEFAULT_AGENT_ID),
            agent_scope=as_text(meta.get("agent_scope"), "shared")
            if as_text(meta.get("agent_scope"), "shared") in {"shared", "codex", "claude"}
            else "shared",
            session_id=as_text(meta.get("session_id")),
            status=status,
            sensitivity=as_text(meta.get("sensitivity"), "private" if track == "user" else "normal"),
            verified_at=verified_at,
            verified_at_source=verified_at_source,
            review_after_days=infer_review_after_days(path, title, memory_type, status, meta),
            mtime=stat.st_mtime,
            size_bytes=stat.st_size,
            line_count=text.count("\n") + 1,
            summary=summary,
            next_hint=next_hint,
            stale_info=stale_info,
            has_open_loop=1 if open_loops else 0,
            open_loop_count=len(open_loops),
            keywords=keywords,
            headings=headings,
            search_text=text,
            indexed_at=indexed_at,
        ),
        open_loops,
    )


def connect() -> sqlite3.Connection:
    STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(STATE_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memory_docs (
          path TEXT PRIMARY KEY,
          rel_path TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          title TEXT NOT NULL,
          memory_type TEXT NOT NULL,
          track TEXT NOT NULL,
          project_id TEXT,
          app_id TEXT DEFAULT 'codex',
          user_id TEXT DEFAULT 'demo-user',
          agent_id TEXT DEFAULT 'codex',
          agent_scope TEXT DEFAULT 'shared',
          session_id TEXT DEFAULT '',
          status TEXT DEFAULT 'active',
          sensitivity TEXT DEFAULT 'normal',
          verified_at TEXT,
          verified_at_source TEXT DEFAULT 'mtime_fallback',
          review_after_days INTEGER DEFAULT 180,
          mtime REAL NOT NULL,
          size_bytes INTEGER NOT NULL,
          line_count INTEGER NOT NULL,
          summary TEXT,
          next_hint TEXT,
          stale_info TEXT,
          has_open_loop INTEGER DEFAULT 0,
          open_loop_count INTEGER DEFAULT 0,
          indexed_at TEXT NOT NULL
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
          path UNINDEXED,
          title,
          rel_path,
          summary,
          keywords,
          headings,
          search_text,
          tokenize = 'unicode61'
        );

        CREATE TABLE IF NOT EXISTS memory_open_loops (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          path TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          title TEXT NOT NULL,
          kind TEXT NOT NULL,
          item TEXT NOT NULL,
          status TEXT DEFAULT 'open',
          indexed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memory_search_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          query TEXT NOT NULL,
          result_count INTEGER NOT NULL,
          used_paths TEXT,
          query_sha256 TEXT,
          query_length INTEGER,
          sources TEXT,
          duration_ms INTEGER,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memory_session_claims (
          session_hash TEXT NOT NULL,
          actor TEXT NOT NULL,
          path TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          claimed_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          completed_at TEXT,
          PRIMARY KEY (session_hash, path)
        );

        CREATE INDEX IF NOT EXISTS idx_memory_docs_track ON memory_docs(track);
        CREATE INDEX IF NOT EXISTS idx_memory_docs_type ON memory_docs(memory_type);
        CREATE INDEX IF NOT EXISTS idx_memory_docs_project ON memory_docs(project_id);
        CREATE INDEX IF NOT EXISTS idx_memory_docs_user_agent_app ON memory_docs(user_id, agent_id, app_id);
        """
    )
    ensure_column(conn, "memory_docs", "verified_at_source", "TEXT DEFAULT 'mtime_fallback'")
    ensure_column(conn, "memory_docs", "review_after_days", "INTEGER DEFAULT 180")
    ensure_column(conn, "memory_docs", "agent_scope", "TEXT DEFAULT 'shared'")
    ensure_column(conn, "memory_docs", "session_id", "TEXT DEFAULT ''")
    ensure_column(conn, "memory_search_log", "query_sha256", "TEXT")
    ensure_column(conn, "memory_search_log", "query_length", "INTEGER")
    ensure_column(conn, "memory_search_log", "sources", "TEXT")
    ensure_column(conn, "memory_search_log", "duration_ms", "INTEGER")
    # Older databases do not have these columns until the migration above runs.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_docs_agent_scope ON memory_docs(agent_scope)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_memory_docs_session ON memory_docs(session_id)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_session_claims_active "
        "ON memory_session_claims(status, actor, session_hash)"
    )
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("memory_index_schema_version", "4"))
    conn.commit()


def iter_markdown_files() -> list[Path]:
    if not VAULT_ROOT.is_dir():
        raise SystemExit(f"AGENT_MEMORY_ROOT does not exist or is not a directory: {VAULT_ROOT}")
    return sorted(path for path in VAULT_ROOT.rglob("*.md") if path.is_file())


def upsert_doc(conn: sqlite3.Connection, doc: MemoryDoc) -> None:
    conn.execute(
        """
        INSERT INTO memory_docs (
          path, rel_path, sha256, title, memory_type, track, project_id, app_id,
          user_id, agent_id, agent_scope, session_id, status, sensitivity, verified_at, verified_at_source,
          review_after_days, mtime, size_bytes, line_count, summary, next_hint, stale_info, has_open_loop,
          open_loop_count, indexed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
          rel_path=excluded.rel_path,
          sha256=excluded.sha256,
          title=excluded.title,
          memory_type=excluded.memory_type,
          track=excluded.track,
          project_id=excluded.project_id,
          app_id=excluded.app_id,
          user_id=excluded.user_id,
          agent_id=excluded.agent_id,
          agent_scope=excluded.agent_scope,
          session_id=excluded.session_id,
          status=excluded.status,
          sensitivity=excluded.sensitivity,
          verified_at=excluded.verified_at,
          verified_at_source=excluded.verified_at_source,
          review_after_days=excluded.review_after_days,
          mtime=excluded.mtime,
          size_bytes=excluded.size_bytes,
          line_count=excluded.line_count,
          summary=excluded.summary,
          next_hint=excluded.next_hint,
          stale_info=excluded.stale_info,
          has_open_loop=excluded.has_open_loop,
          open_loop_count=excluded.open_loop_count,
          indexed_at=excluded.indexed_at
        """,
        (
            str(doc.path),
            doc.rel_path,
            doc.sha256,
            doc.title,
            doc.memory_type,
            doc.track,
            doc.project_id,
            doc.app_id,
            doc.user_id,
            doc.agent_id,
            doc.agent_scope,
            doc.session_id,
            doc.status,
            doc.sensitivity,
            doc.verified_at,
            doc.verified_at_source,
            doc.review_after_days,
            doc.mtime,
            doc.size_bytes,
            doc.line_count,
            doc.summary,
            doc.next_hint,
            doc.stale_info,
            doc.has_open_loop,
            doc.open_loop_count,
            doc.indexed_at,
        ),
    )


def insert_fts(conn: sqlite3.Connection, doc: MemoryDoc) -> None:
    conn.execute(
        """
        INSERT INTO memory_fts(path, title, rel_path, summary, keywords, headings, search_text)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (str(doc.path), doc.title, doc.rel_path, doc.summary, doc.keywords, doc.headings, doc.search_text),
    )


def scan(conn: sqlite3.Connection) -> None:
    init_db(conn)
    indexed_at = utc_now()
    conn.execute("DELETE FROM memory_docs")
    conn.execute("DELETE FROM memory_fts")
    conn.execute("DELETE FROM memory_open_loops")
    files = iter_markdown_files()
    for path in files:
        doc, open_loops = load_doc(path, indexed_at)
        upsert_doc(conn, doc)
        insert_fts(conn, doc)
        conn.executemany(
            """
            INSERT INTO memory_open_loops(path, rel_path, title, kind, item, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            open_loops,
        )
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("memory_index_last_scan_at", indexed_at))
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("memory_index_doc_count", str(len(files))))


def query_chunks(raw_query: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_.+-]+|[\u3400-\u9fff]+", raw_query.strip())


def lexical_terms(raw_query: str, limit: int = 18) -> list[str]:
    terms: list[str] = []
    for chunk in query_chunks(raw_query):
        if re.fullmatch(r"[\u3400-\u9fff]+", chunk):
            if len(chunk) <= 6:
                terms.append(chunk)
            gram_size = 2 if len(chunk) <= 8 else 3
            terms.extend(chunk[index : index + gram_size] for index in range(len(chunk) - gram_size + 1))
        else:
            terms.append(chunk.lower())
    return list(dict.fromkeys(term for term in terms if term))[:limit]


def fts_query(raw_query: str) -> str:
    terms = query_chunks(raw_query)
    if not terms:
        return '""'
    escaped = [term.replace('"', '""') for term in terms[:8]]
    return " OR ".join(f'"{term}"' for term in escaped)


def row_matches_filters(
    row: sqlite3.Row,
    track: str,
    memory_type: str,
    project_id: str,
    user_id: str,
    agent_id: str,
    app_id: str,
    session_id: str,
    status: str,
    has_open_loop: bool,
) -> bool:
    if track and row["track"] != track:
        return False
    if memory_type and row["memory_type"] != memory_type:
        return False
    if project_id and project_id.lower() not in str(row["project_id"]).lower():
        return False
    if user_id and row["user_id"] != user_id:
        return False
    if agent_id and row["agent_id"] != agent_id:
        return False
    if app_id and row["app_id"] != app_id:
        return False
    if session_id and row["session_id"] != session_id:
        return False
    if status and row["status"] != status:
        return False
    if has_open_loop and int(row["has_open_loop"] or 0) != 1:
        return False
    return True


def score_row(row: sqlite3.Row, terms: list[str]) -> int:
    if not terms:
        return 0
    fields = {
        "title": str(row["title"]).lower(),
        "rel_path": str(row["rel_path"]).lower(),
        "summary": str(row["summary"] or "").lower(),
        "search_text": str(row["search_text"] or "").lower(),
    }
    score = 0
    matched = 0
    for term in terms:
        needle = term.lower()
        term_matched = False
        if needle in fields["title"]:
            score += 8
            term_matched = True
        if needle in fields["rel_path"]:
            score += 5
            term_matched = True
        if needle in fields["summary"]:
            score += 4
            term_matched = True
        if needle in fields["search_text"]:
            score += 1
            term_matched = True
        if term_matched:
            matched += 1
    if matched == len(terms):
        score += 10
    score += min(matched, 5) * 2
    if row["memory_type"] in {"routing", "directory_index", "template"}:
        score -= 4
    if int(row["has_open_loop"] or 0):
        score += 1
    return score


def dedupe_and_rank(rows: list[sqlite3.Row], query: str, limit: int) -> list[sqlite3.Row]:
    terms = lexical_terms(query)
    by_path: dict[str, sqlite3.Row] = {}
    for row in rows:
        by_path.setdefault(row["path"], row)
    ranked = sorted(
        by_path.values(),
        key=lambda row: (score_row(row, terms), float(row["mtime"] or 0)),
        reverse=True,
    )
    return ranked[:limit]


def search(
    conn: sqlite3.Connection,
    query: str,
    limit: int,
    track: str = "",
    memory_type: str = "",
    project_id: str = "",
    user_id: str = "",
    agent_id: str = "",
    app_id: str = "",
    session_id: str = "",
    status: str = "",
    has_open_loop: bool = False,
) -> list[sqlite3.Row]:
    conn.row_factory = sqlite3.Row
    init_db(conn)
    rows: list[sqlite3.Row] = []
    try:
        rows = list(
            conn.execute(
                """
                SELECT d.*, memory_fts.search_text AS search_text, snippet(memory_fts, 6, '[', ']', '...', 12) AS hit
                FROM memory_fts
                JOIN memory_docs d ON d.path = memory_fts.path
                WHERE memory_fts MATCH ?
                ORDER BY bm25(memory_fts)
                LIMIT ?
                """,
                (fts_query(query), max(limit * 12, 50)),
            )
        )
    except sqlite3.Error:
        rows = []

    seen = {row["path"] for row in rows}
    terms = lexical_terms(query)
    if terms:
        like_parts: list[str] = []
        params: list[object] = []
        for term in terms[:6]:
            like = f"%{term}%"
            like_parts.append(
                "(memory_fts.title LIKE ? OR memory_fts.rel_path LIKE ? OR memory_fts.summary LIKE ? OR memory_fts.search_text LIKE ?)"
            )
            params.extend([like, like, like, like])
        fallback = list(
            conn.execute(
                f"""
                SELECT d.*, memory_fts.search_text AS search_text, substr(memory_fts.summary, 1, 160) AS hit
                FROM memory_fts
                JOIN memory_docs d ON d.path = memory_fts.path
                WHERE {' OR '.join(like_parts)}
                ORDER BY d.has_open_loop DESC, d.mtime DESC
                LIMIT ?
                """,
                [*params, max(limit * 20, 80)],
            )
        )
        for row in fallback:
            if row["path"] not in seen:
                rows.append(row)
                seen.add(row["path"])

    rows = [
        row
        for row in rows
        if row_matches_filters(
            row,
            track,
            memory_type,
            project_id,
            user_id,
            agent_id,
            app_id,
            session_id,
            status,
            has_open_loop,
        )
    ]
    return dedupe_and_rank(rows, query, limit)


def print_search(
    conn: sqlite3.Connection,
    query: str,
    limit: int,
    include_open_loops: bool,
    track: str,
    memory_type: str,
    project_id: str,
    user_id: str,
    agent_id: str,
    app_id: str,
    session_id: str,
    status: str,
    has_open_loop: bool,
) -> None:
    started = time.monotonic()
    rows = search(
        conn,
        query,
        limit,
        track,
        memory_type,
        project_id,
        user_id,
        agent_id,
        app_id,
        session_id,
        status,
        has_open_loop,
    )
    print(f"query={query}")
    if any([track, memory_type, project_id, user_id, agent_id, app_id, session_id, status, has_open_loop]):
        print(
            "filters="
            f"track={track or '*'} "
            f"memory_type={memory_type or '*'} "
            f"project_id={project_id or '*'} "
            f"user_id={user_id or '*'} "
            f"agent_id={agent_id or '*'} "
            f"app_id={app_id or '*'} "
            f"session_id={session_id or '*'} "
            f"status={status or '*'} "
            f"has_open_loop={has_open_loop}"
        )
    print(f"results={len(rows)}")
    for index, row in enumerate(rows, 1):
        print(f"{index}. {row['rel_path']}")
        print(f"   title: {row['title']}")
        print(
            "   type: "
            f"{row['memory_type']} track={row['track']} project_id={row['project_id']} "
            f"user_id={row['user_id']} agent_id={row['agent_id']} app_id={row['app_id']} status={row['status']}"
        )
        print(f"   verified_at: {row['verified_at']} source={row['verified_at_source']}")
        print(f"   summary: {str(row['summary'] or '')[:220]}")
        hit = str(row["hit"] or "").replace("\n", " ")
        print(f"   hit: {hit[:220]}")
        if include_open_loops:
            loops = conn.execute(
                "SELECT kind, item FROM memory_open_loops WHERE path=? AND status='open' LIMIT 3",
                (row["path"],),
            ).fetchall()
            for kind, item in loops:
                print(f"   open_loop[{kind}]: {item[:180]}")
    digest = sha256_text(query)
    conn.execute(
        """
        INSERT INTO memory_search_log(
          query, result_count, used_paths, query_sha256, query_length, sources, duration_ms, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"[redacted:{digest[:12]}]",
            len(rows),
            ",".join(row["rel_path"] for row in rows),
            digest,
            len(query),
            "sqlite",
            round((time.monotonic() - started) * 1000),
            utc_now(),
        ),
    )


def print_report(conn: sqlite3.Connection) -> None:
    init_db(conn)
    doc_count = conn.execute("SELECT COUNT(*) FROM memory_docs").fetchone()[0]
    loop_count = conn.execute("SELECT COUNT(*) FROM memory_open_loops WHERE status='open'").fetchone()[0]
    last_scan = conn.execute("SELECT value FROM meta WHERE key='memory_index_last_scan_at'").fetchone()
    print(f"vault_root={VAULT_ROOT}")
    print(f"state_db={STATE_DB}")
    print(f"memory_docs={doc_count}")
    print(f"memory_open_loops={loop_count}")
    print(f"last_scan_at={last_scan[0] if last_scan else ''}")
    for track, count in conn.execute(
        "SELECT track, COUNT(*) AS item_count FROM memory_docs GROUP BY track ORDER BY item_count DESC, track"
    ):
        print(f"track[{track}]={count}")
    for memory_type, count in conn.execute(
        "SELECT memory_type, COUNT(*) AS item_count FROM memory_docs GROUP BY memory_type ORDER BY item_count DESC, memory_type"
    ):
        print(f"type[{memory_type}]={count}")


def generated_index_candidate(conn: sqlite3.Connection) -> str:
    """Generate a deterministic navigation view from indexed Markdown metadata."""
    init_db(conn)
    rows = conn.execute(
        """
        SELECT rel_path, title, memory_type, track, project_id, status, summary
        FROM memory_docs
        ORDER BY
          CASE track
            WHEN 'user' THEN 1
            WHEN 'project' THEN 2
            WHEN 'workflow' THEN 3
            WHEN 'decision' THEN 4
            WHEN 'agent' THEN 5
            WHEN 'routing' THEN 6
            ELSE 9
          END,
          rel_path
        """
    ).fetchall()
    lines = [
        "# Agent Memory INDEX candidate",
        "",
        f"Generated at: {utc_now()}",
        "",
        "This navigation candidate is derived from Markdown/frontmatter through SQLite. Review the diff before replacing a curated INDEX.md.",
    ]
    current_track = ""
    for row in rows:
        rel_path, title, memory_type, track, project_id, status, summary = row
        normalized_track = track or "uncategorized"
        if normalized_track != current_track:
            current_track = normalized_track
            lines.extend(["", f"## {current_track}", ""])
        compact_summary = (summary or "").replace("\n", " ").strip()
        if len(compact_summary) > 120:
            compact_summary = compact_summary[:117] + "..."
        metadata = str(memory_type)
        if project_id:
            metadata += f"; {project_id}"
        if status and status != "active":
            metadata += f"; status={status}"
        suffix = f"; {compact_summary}" if compact_summary else ""
        lines.append(f"- `{rel_path}`: {title} ({metadata}){suffix}")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and query the full Agent Memory SQLite index.")
    parser.add_argument("--init", action="store_true", help="Create or migrate the index schema.")
    parser.add_argument("--scan", action="store_true", help="Scan all Markdown files into SQLite.")
    parser.add_argument("--report", action="store_true", help="Print index summary.")
    parser.add_argument("--search", help="Search the local memory index.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Maximum search results.")
    parser.add_argument("--include-open-loops", action="store_true", help="Show open loop snippets for search hits.")
    parser.add_argument("--track", default="", help="Filter by track, e.g. project, workflow, user, agent.")
    parser.add_argument("--memory-type", default="", help="Filter by memory_type.")
    parser.add_argument("--project-id", default="", help="Filter by project_id substring.")
    parser.add_argument("--user-id", default="", help="Filter by user_id.")
    parser.add_argument("--agent-id", default="", help="Filter by agent_id.")
    parser.add_argument("--app-id", default="", help="Filter by app_id.")
    parser.add_argument("--session-id", default="", help="Filter by session_id.")
    parser.add_argument("--status", default="", help="Filter by status.")
    parser.add_argument("--has-open-loop", action="store_true", help="Only return docs with open loops.")
    parser.add_argument("--gen-index-candidate", action="store_true", help="Generate an INDEX.md candidate from SQLite.")
    parser.add_argument("--output", default="", help="Optional output path for --gen-index-candidate.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not (args.init or args.scan or args.report or args.search or args.gen_index_candidate):
        args.init = True
        args.scan = True
        args.report = True
    with connect() as conn:
        if args.init:
            init_db(conn)
        if args.scan:
            scan(conn)
        if args.search:
            print_search(
                conn,
                args.search,
                max(args.limit, 1),
                args.include_open_loops,
                args.track,
                args.memory_type,
                args.project_id,
                args.user_id,
                args.agent_id,
                args.app_id,
                args.session_id,
                args.status,
                args.has_open_loop,
            )
        if args.report or args.scan:
            print_report(conn)
        if args.gen_index_candidate:
            candidate = generated_index_candidate(conn)
            if args.output:
                output_path = Path(args.output).expanduser().resolve()
                output_path.write_text(candidate, encoding="utf-8")
                print(f"index_candidate={output_path}")
            else:
                print(candidate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
