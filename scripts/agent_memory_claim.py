#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from agent_memory_env import env_value


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = Path(
    os.path.expandvars(env_value("ROOT", str(RUNTIME_ROOT / "templates" / "vault")))
).expanduser().resolve()
STATE_DB = Path(
    os.path.expandvars(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite"))
).expanduser().resolve()
ACTOR_SESSION_ENV_KEYS = {
    "codex": ("AGENT_MEMORY_SESSION_ID", "CODEX_THREAD_ID"),
    "claude": ("AGENT_MEMORY_SESSION_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID"),
    "human": ("AGENT_MEMORY_SESSION_ID",),
    "migration": ("AGENT_MEMORY_SESSION_ID",),
    "test": ("AGENT_MEMORY_SESSION_ID",),
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def session_value(explicit: str = "", actor: str = "codex") -> str:
    if explicit.strip():
        return explicit.strip()
    for key in ACTOR_SESSION_ENV_KEYS.get(actor, ("AGENT_MEMORY_SESSION_ID",)):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def session_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if value else ""


def connect() -> sqlite3.Connection:
    STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(STATE_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    ensure_schema(conn)
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
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
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_file_observations (
          path TEXT PRIMARY KEY,
          rel_path TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          actor TEXT NOT NULL,
          session_hash TEXT NOT NULL DEFAULT '',
          observed_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_session_claims_active "
        "ON memory_session_claims(status, actor, session_hash)"
    )
    conn.commit()


def record_file_observations(raw_session_id: str, actor: str, paths: list[Path]) -> int:
    rows: list[tuple[str, str, str]] = []
    for raw_path in paths:
        path = raw_path.resolve()
        if not path.is_file() or path.suffix.lower() != ".md":
            continue
        try:
            rel_path = path.relative_to(VAULT_ROOT).as_posix()
        except ValueError:
            continue
        rows.append((str(path), rel_path, file_sha256(path)))
    if not rows:
        return 0
    now = utc_now()
    hashed = session_hash(raw_session_id)
    with connect() as conn:
        for path, rel_path, digest in rows:
            conn.execute(
                """
                INSERT INTO memory_file_observations (
                  path, rel_path, sha256, actor, session_hash, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                  rel_path=excluded.rel_path,
                  sha256=excluded.sha256,
                  actor=excluded.actor,
                  session_hash=excluded.session_hash,
                  observed_at=excluded.observed_at
                """,
                (path, rel_path, digest, actor, hashed, now),
            )
        conn.commit()
    return len(rows)


def normalize_claim_path(raw: str) -> tuple[Path, str]:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    else:
        path = path.resolve()
    try:
        rel_path = path.relative_to(VAULT_ROOT).as_posix()
    except ValueError as exc:
        raise ValueError(f"claim path is outside the memory vault: {path}") from exc
    if path.suffix.lower() != ".md":
        raise ValueError(f"claim path is not Markdown: {path}")
    if not path.exists():
        raise ValueError(f"claim path does not exist: {path}")
    return path, rel_path


def claim_paths(actor: str, raw_session_id: str, paths: list[str]) -> list[dict[str, str]]:
    hashed = session_hash(raw_session_id)
    if not hashed:
        raise ValueError("session id is required; pass --session-id or use a supported host session environment")
    normalized = [normalize_claim_path(raw) for raw in paths]
    now = utc_now()
    with connect() as conn:
        for path, rel_path in normalized:
            conn.execute(
                """
                INSERT INTO memory_session_claims (
                  session_hash, actor, path, rel_path, status, claimed_at, updated_at, completed_at
                ) VALUES (?, ?, ?, ?, 'active', ?, ?, NULL)
                ON CONFLICT(session_hash, path) DO UPDATE SET
                  actor=excluded.actor,
                  rel_path=excluded.rel_path,
                  status='active',
                  updated_at=excluded.updated_at,
                  completed_at=NULL
                """,
                (hashed, actor, str(path), rel_path, now, now),
            )
        conn.commit()
    return [{"path": str(path), "rel_path": rel_path} for path, rel_path in normalized]


def active_claim_rows(raw_session_id: str, actor: str = "") -> list[dict[str, str]]:
    hashed = session_hash(raw_session_id)
    if not hashed:
        return []
    query = (
        "SELECT session_hash, actor, path, rel_path, status, claimed_at, updated_at "
        "FROM memory_session_claims WHERE session_hash=? AND status='active'"
    )
    params: list[str] = [hashed]
    if actor:
        query += " AND actor=?"
        params.append(actor)
    query += " ORDER BY rel_path"
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [{key: str(row[key] or "") for key in row.keys()} for row in rows]


def parsed_time(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def all_active_claim_rows(max_age_hours: float | None = None) -> list[dict[str, str]]:
    if max_age_hours is not None and max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT session_hash, actor, path, rel_path, status, claimed_at, updated_at
            FROM memory_session_claims
            WHERE status='active'
            ORDER BY actor, session_hash, rel_path
            """
        ).fetchall()
    payloads = [{key: str(row[key] or "") for key in row.keys()} for row in rows]
    if max_age_hours is None:
        return payloads
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=max_age_hours)
    return [row for row in payloads if (parsed_time(row["updated_at"]) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) >= cutoff]


def stale_active_claim_rows(max_age_hours: float = 24) -> list[dict[str, str]]:
    if max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    rows = all_active_claim_rows()
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=max_age_hours)
    return [row for row in rows if (parsed_time(row["updated_at"]) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) < cutoff]


def expire_stale_claims(max_age_hours: float = 24, apply: bool = False) -> tuple[list[dict[str, str]], int]:
    rows = stale_active_claim_rows(max_age_hours)
    if not apply or not rows:
        return rows, 0
    now = utc_now()
    changed = 0
    with connect() as conn:
        for row in rows:
            cursor = conn.execute(
                """
                UPDATE memory_session_claims
                SET status='expired', completed_at=?, updated_at=?
                WHERE session_hash=? AND path=? AND status='active' AND updated_at=?
                """,
                (now, now, row["session_hash"], row["path"], row["updated_at"]),
            )
            changed += int(cursor.rowcount)
        conn.commit()
    return rows, changed


def complete_claim_paths(raw_session_id: str, actor: str, paths: list[Path]) -> int:
    hashed = session_hash(raw_session_id)
    if not hashed or not paths:
        return 0
    now = utc_now()
    with connect() as conn:
        placeholders = ",".join("?" for _ in paths)
        params: list[str] = [now, now, hashed, actor, *(str(path.resolve()) for path in paths)]
        cursor = conn.execute(
            f"""
            UPDATE memory_session_claims
            SET status='completed', completed_at=?, updated_at=?
            WHERE session_hash=? AND actor=? AND status='active'
              AND path IN ({placeholders})
            """,
            params,
        )
        conn.commit()
        return int(cursor.rowcount)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Track per-session ownership of shared memory files.")
    parser.add_argument("--actor", choices=("codex", "claude", "human", "migration", "test"), default="codex")
    parser.add_argument("--session-id", default="")
    parser.add_argument("--json", action="store_true")
    subparsers = parser.add_subparsers(dest="action", required=True)
    claim_parser = subparsers.add_parser("claim", help="Claim one or more Markdown files for this session.")
    claim_parser.add_argument("--file", action="append", required=True)
    subparsers.add_parser("list", help="List active claims for this session.")
    subparsers.add_parser("list-all", help="List all active claims.")
    expire_parser = subparsers.add_parser("expire-stale", help="Preview or expire abandoned active claims.")
    expire_parser.add_argument("--older-than-hours", type=float, default=24)
    expire_parser.add_argument("--apply", action="store_true", help="Mark matching claims expired; default is preview only.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw_session_id = session_value(args.session_id, args.actor)
    applied = 0
    try:
        if args.action == "claim":
            rows = claim_paths(args.actor, raw_session_id, args.file)
        elif args.action == "list-all":
            rows = all_active_claim_rows()
        elif args.action == "expire-stale":
            rows, applied = expire_stale_claims(args.older_than_hours, args.apply)
        else:
            if not raw_session_id:
                raise ValueError("session id is required; pass --session-id or use a supported host session environment")
            rows = active_claim_rows(raw_session_id, args.actor)
    except (ValueError, sqlite3.Error) as exc:
        payload: dict[str, Any] = {"ok": False, "error": str(exc), "action": args.action}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"claim_error={exc}")
        return 2
    payload = {
        "ok": True,
        "action": args.action,
        "actor": args.actor,
        "session_hash": session_hash(raw_session_id),
        "count": len(rows),
        "claims": rows,
        "applied": applied,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"claims={len(rows)} applied={applied} actor={args.actor} session={payload['session_hash']}")
        for row in rows:
            print(row.get("rel_path", row.get("path", "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
