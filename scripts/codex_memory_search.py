#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"
DEFAULT_VAULT_ROOT = REPO_ROOT / "templates" / "vault"
VAULT_ROOT = Path(os.path.expandvars(os.environ.get("CODEX_MEMORY_ROOT", str(DEFAULT_VAULT_ROOT)))).expanduser().resolve()
STATE_DB = Path(
    os.path.expandvars(os.environ.get("CODEX_MEMORY_STATE_DB", "$HOME/.config/codex-memory/state.sqlite"))
).expanduser().resolve()
ZVEC_SCRIPT = SCRIPT_ROOT / "codex_memory_zvec_index.py"

if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import codex_memory_index as memory_index  # noqa: E402


@dataclass
class SearchResult:
    path: str
    rel_path: str
    title: str = ""
    memory_type: str = ""
    track: str = ""
    project_id: str = ""
    status: str = ""
    verified_at: str = ""
    verified_at_source: str = ""
    user_id: str = ""
    agent_id: str = ""
    app_id: str = ""
    session_id: str = ""
    has_open_loop: int = 0
    summary: str = ""
    hit: str = ""
    score: float = 0.0
    sources: set[str] = field(default_factory=set)
    source_details: dict[str, Any] = field(default_factory=dict)

    def merge(self, other: "SearchResult") -> None:
        self.sources.update(other.sources)
        self.score += other.score
        self.source_details.update(other.source_details)
        for attr in (
            "title", "memory_type", "track", "project_id", "status", "verified_at",
            "verified_at_source", "user_id", "agent_id", "app_id", "session_id", "summary", "hit",
        ):
            if not getattr(self, attr) and getattr(other, attr):
                setattr(self, attr, getattr(other, attr))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "title": self.title,
            "memory_type": self.memory_type,
            "track": self.track,
            "project_id": self.project_id,
            "status": self.status,
            "verified_at": self.verified_at,
            "verified_at_source": self.verified_at_source,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "app_id": self.app_id,
            "session_id": self.session_id,
            "summary": self.summary,
            "hit": self.hit,
            "sources": sorted(self.sources),
            "score": round(self.score, 4),
            "path": self.path,
            "source_details": self.source_details,
        }


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


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


def coverage(query: str, text: str) -> float:
    query_tokens = tokenize(query)
    text_tokens = tokenize(text)
    if not query_tokens or not text_tokens:
        return 0.0
    return len(query_tokens & text_tokens) / len(query_tokens)


def compact_match_text(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9\u3400-\u9fff]+", "", text).lower()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(STATE_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def row_to_result(row: sqlite3.Row, rank: int, query: str) -> SearchResult:
    searchable = " ".join(str(row[key] or "") for key in ("title", "rel_path", "summary", "hit"))
    term_coverage = coverage(query, searchable)
    compact_query = compact_match_text(query)
    compact_title = compact_match_text(str(row["title"] or ""))
    exact_bonus = 4.0 if compact_query and compact_query in compact_title else 0.0
    return SearchResult(
        path=str(row["path"]),
        rel_path=str(row["rel_path"]),
        title=str(row["title"] or ""),
        memory_type=str(row["memory_type"] or ""),
        track=str(row["track"] or ""),
        project_id=str(row["project_id"] or ""),
        status=str(row["status"] or ""),
        verified_at=str(row["verified_at"] or ""),
        verified_at_source=str(row["verified_at_source"] or ""),
        user_id=str(row["user_id"] or ""),
        agent_id=str(row["agent_id"] or ""),
        app_id=str(row["app_id"] or ""),
        session_id=str(row["session_id"] or ""),
        has_open_loop=int(row["has_open_loop"] or 0),
        summary=str(row["summary"] or ""),
        hit=str(row["hit"] or "").replace("\n", " "),
        score=(1.0 / max(rank, 1)) + (term_coverage * 3.0) + exact_bonus,
        sources={"sqlite"},
        source_details={"sqlite_rank": rank, "term_coverage": round(term_coverage, 4), "exact_title_bonus": exact_bonus},
    )


def enrich_from_db(result: SearchResult, conn: sqlite3.Connection) -> SearchResult:
    row = conn.execute(
        """
        SELECT path, rel_path, title, memory_type, track, project_id, status,
               verified_at, verified_at_source, user_id, agent_id, app_id,
               session_id, has_open_loop, summary
        FROM memory_docs
        WHERE path=? OR rel_path=?
        LIMIT 1
        """,
        (result.path, result.rel_path),
    ).fetchone()
    if not row:
        return result
    result.path = str(row["path"])
    result.rel_path = str(row["rel_path"])
    result.title = result.title or str(row["title"] or "")
    result.memory_type = result.memory_type or str(row["memory_type"] or "")
    result.track = result.track or str(row["track"] or "")
    result.project_id = result.project_id or str(row["project_id"] or "")
    result.status = result.status or str(row["status"] or "")
    result.verified_at = result.verified_at or str(row["verified_at"] or "")
    result.verified_at_source = result.verified_at_source or str(row["verified_at_source"] or "")
    result.user_id = result.user_id or str(row["user_id"] or "")
    result.agent_id = result.agent_id or str(row["agent_id"] or "")
    result.app_id = result.app_id or str(row["app_id"] or "")
    result.session_id = result.session_id or str(row["session_id"] or "")
    result.has_open_loop = int(row["has_open_loop"] or 0)
    result.summary = result.summary or str(row["summary"] or "")
    return result


def sqlite_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str]]:
    if not STATE_DB.exists():
        return [], [f"sqlite index missing: {STATE_DB}"]
    try:
        with memory_index.connect() as conn:
            rows = memory_index.search(
                conn,
                args.query,
                max(args.limit * 2, args.limit),
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
            return [row_to_result(row, rank, args.query) for rank, row in enumerate(rows, 1)], []
    except Exception as exc:  # pragma: no cover
        return [], [f"sqlite search failed: {exc}"]


def command_env_offline() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env.setdefault("HF_HUB_OFFLINE", "1")
    env.setdefault("TRANSFORMERS_OFFLINE", "1")
    return env


def zvec_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str]]:
    if args.no_zvec:
        return [], []
    if not ZVEC_SCRIPT.exists():
        return [], [f"zvec script missing: {ZVEC_SCRIPT}"]
    command = [str(ZVEC_SCRIPT), "--search", args.query, "--limit", str(max(args.limit * 2, args.limit)), "--json"]
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=args.zvec_timeout,
            env=command_env_offline(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], [f"zvec search timed out after {args.zvec_timeout}s"]
    except OSError as exc:
        return [], [f"zvec search failed to start: {exc}"]
    if completed.returncode != 0 and not completed.stdout.strip():
        detail = completed.stderr.strip() or f"returncode={completed.returncode}"
        return [], [f"zvec search failed: {detail}"]
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        detail = completed.stderr.strip() or completed.stdout.strip()[:300]
        return [], [f"zvec returned non-json output: {detail}"]
    if payload.get("error"):
        return [], [f"zvec search failed: {payload['error']}"]
    rows = payload.get("results", [])
    if not isinstance(rows, list):
        return [], ["zvec returned invalid result shape"]
    results: list[SearchResult] = []
    with connect() as conn:
        for rank, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                continue
            try:
                vector_score = float(row.get("vector_score", row.get("score", 0)))
                reconcile_score = float(row.get("score", vector_score))
            except (TypeError, ValueError):
                continue
            if vector_score > args.zvec_max_distance:
                continue
            semantic_quality = max(0.0, 1.0 - (vector_score / args.zvec_max_distance))
            result = SearchResult(
                path=str(row.get("path") or ""),
                rel_path=str(row.get("rel_path") or ""),
                title=str(row.get("title") or ""),
                memory_type=str(row.get("memory_type") or ""),
                track=str(row.get("track") or ""),
                project_id=str(row.get("project_id") or ""),
                verified_at=str(row.get("verified_at") or ""),
                summary=str(row.get("summary") or ""),
                hit=str(row.get("summary") or ""),
                score=(0.8 / max(rank, 1)) + (semantic_quality * 2.0)
                + coverage(args.query, " ".join(str(row.get(key) or "") for key in ("title", "rel_path", "summary")))
                * 2.0,
                sources={"zvec"},
                source_details={"zvec_rank": rank, "zvec_score": reconcile_score, "zvec_raw_distance": vector_score},
            )
            results.append(enrich_from_db(result, conn))
    return results, []


def rg_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str]]:
    if not args.force_rg:
        return [], []
    command = ["rg", "--line-number", "--ignore-case", "--fixed-strings", "--", args.query, str(VAULT_ROOT)]
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=args.rg_timeout, check=False)
    except FileNotFoundError:
        return [], ["rg not found"]
    except subprocess.TimeoutExpired:
        return [], [f"rg timed out after {args.rg_timeout}s"]
    if completed.returncode not in {0, 1}:
        return [], [completed.stderr.strip() or f"rg failed: {completed.returncode}"]
    results: list[SearchResult] = []
    seen: set[str] = set()
    with connect() as conn:
        for line in completed.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            path = str(Path(parts[0]).resolve())
            if path in seen:
                continue
            seen.add(path)
            try:
                rel_path = Path(path).relative_to(VAULT_ROOT).as_posix()
            except ValueError:
                rel_path = path
            result = SearchResult(
                path=path,
                rel_path=rel_path,
                hit=parts[2].strip(),
                score=0.35 / max(len(seen), 1),
                sources={"rg"},
                source_details={"rg_line": parts[1]},
            )
            results.append(enrich_from_db(result, conn))
            if len(results) >= max(args.limit * 2, args.limit):
                break
    return results, []


def merge_results(result_groups: list[list[SearchResult]]) -> list[SearchResult]:
    merged: dict[str, SearchResult] = {}
    for group in result_groups:
        for item in group:
            key = item.path or item.rel_path
            if not key:
                continue
            if key in merged:
                merged[key].merge(item)
            else:
                merged[key] = item
    rows = list(merged.values())
    rows.sort(key=lambda item: (item.score, item.verified_at), reverse=True)
    return rows


def result_matches_filters(result: SearchResult, args: argparse.Namespace) -> bool:
    for value, actual in (
        (args.track, result.track),
        (args.memory_type, result.memory_type),
        (args.user_id, result.user_id),
        (args.agent_id, result.agent_id),
        (args.app_id, result.app_id),
        (args.session_id, result.session_id),
    ):
        if value and value != actual:
            return False
    if args.project_id and args.project_id.lower() not in result.project_id.lower():
        return False
    if args.status and result.status != args.status:
        return False
    if not args.status and not args.include_inactive and result.status != "active":
        return False
    if args.has_open_loop and result.has_open_loop != 1:
        return False
    if not args.memory_type and not args.include_supporting and result.memory_type in {"template", "directory_index"}:
        return False
    return bool(result.path and result.rel_path)


def log_search(query: str, rows: list[SearchResult], duration_ms: int) -> None:
    try:
        with connect() as conn:
            memory_index.init_db(conn)
            digest = hashlib.sha256(query.encode("utf-8")).hexdigest()
            sources = sorted({source for row in rows for source in row.sources})
            conn.execute(
                """
                INSERT INTO memory_search_log(
                  query, result_count, used_paths, query_sha256, query_length,
                  sources, duration_ms, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"[redacted:{digest[:12]}]", len(rows), ",".join(row.rel_path for row in rows),
                    digest, len(query), ",".join(sources), duration_ms, utc_now(),
                ),
            )
    except sqlite3.Error:
        return


def run_search(args: argparse.Namespace) -> tuple[list[SearchResult], list[str]]:
    started = time.monotonic()
    warnings: list[str] = []
    tasks = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        tasks.append(executor.submit(sqlite_search, args))
        tasks.append(executor.submit(zvec_search, args))
        if args.force_rg:
            tasks.append(executor.submit(rg_search, args))
        for future in as_completed(tasks):
            try:
                rows, task_warnings = future.result()
            except Exception as exc:  # pragma: no cover
                rows, task_warnings = [], [f"search task failed: {exc}"]
            warnings.extend(task_warnings)
            future.rows = rows  # type: ignore[attr-defined]
    rows = merge_results([getattr(task, "rows", []) for task in tasks])
    rows = [row for row in rows if result_matches_filters(row, args)][: args.limit]
    log_search(args.query, rows, round((time.monotonic() - started) * 1000))
    return rows, warnings


def print_human(query: str, rows: list[SearchResult], warnings: list[str]) -> None:
    print(f"query={query}")
    print(f"results={len(rows)}")
    for warning in warnings:
        print(f"warning: {warning}")
    for index, row in enumerate(rows, 1):
        print(f"{index}. {row.rel_path}")
        print(f"   title: {row.title}")
        print(f"   type: {row.memory_type} track={row.track} project_id={row.project_id} status={row.status}")
        print(f"   verified_at: {row.verified_at} source={row.verified_at_source}")
        print(f"   sources: {','.join(sorted(row.sources))} score={round(row.score, 4)}")
        if row.summary:
            print(f"   summary: {row.summary[:240]}")
        if row.hit:
            print(f"   hit: {row.hit[:240]}")
        print(f"   path: {row.path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unified Codex memory search: SQLite FTS plus optional Zvec semantic results.")
    parser.add_argument("query", nargs="?", help="Search query.")
    parser.add_argument("--search", dest="search", help="Search query, alternative to positional query.")
    parser.add_argument("--limit", type=int, default=5, help="Maximum merged results.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--no-zvec", action="store_true", help="Skip semantic Zvec search.")
    parser.add_argument("--force-rg", action="store_true", help="Also run rg as a manual fallback.")
    parser.add_argument("--zvec-timeout", type=int, default=45, help="Seconds before Zvec search times out.")
    parser.add_argument("--zvec-max-distance", type=float, default=0.72, help="Discard farther semantic results.")
    parser.add_argument("--rg-timeout", type=int, default=15, help="Seconds before rg fallback times out.")
    parser.add_argument("--track", default="", help="Filter all results by track.")
    parser.add_argument("--memory-type", default="", help="Filter all results by memory_type.")
    parser.add_argument("--project-id", default="", help="Filter all results by project_id substring.")
    parser.add_argument("--user-id", default="", help="Filter all results by user_id.")
    parser.add_argument("--agent-id", default="", help="Filter all results by agent_id.")
    parser.add_argument("--app-id", default="", help="Filter all results by app_id.")
    parser.add_argument("--session-id", default="", help="Filter all results by session_id.")
    parser.add_argument("--status", default="", help="Filter all results by status.")
    parser.add_argument("--has-open-loop", action="store_true", help="Only return docs with open loops.")
    parser.add_argument("--include-inactive", action="store_true", help="Include candidate/outdated statuses.")
    parser.add_argument("--include-supporting", action="store_true", help="Include templates and directory indexes.")
    args = parser.parse_args()
    args.query = args.search or args.query
    if not args.query:
        parser.error("query is required")
    args.limit = max(args.limit, 1)
    return args


def main() -> int:
    args = parse_args()
    rows, warnings = run_search(args)
    if args.json:
        print(json.dumps({"query": args.query, "results": [row.to_dict() for row in rows], "warnings": warnings}, ensure_ascii=False, indent=2))
    else:
        print_human(args.query, rows, warnings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
