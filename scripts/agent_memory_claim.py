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
import subprocess
import time
from pathlib import Path
from typing import Any

from agent_memory_env import assert_runtime_ready, env_value, expand_path
from agent_memory_lock import try_lock, unlock
import agent_memory_intent as write_intent
from agent_memory_state import absolute_path, secure_sqlite_connect


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(RUNTIME_ROOT / "templates" / "vault"))).resolve()
STATE_DB = absolute_path(expand_path(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite")))
CONFIG_ROOT = expand_path(env_value("CONFIG_ROOT", "$HOME/.config/agent-memory")).resolve()


def find_default_git_root() -> Path:
    for candidate in (VAULT_ROOT, *VAULT_ROOT.parents):
        if (candidate / ".git").exists():
            return candidate.resolve()
    return VAULT_ROOT.resolve()


GIT_ROOT = expand_path(env_value("GIT_ROOT", str(find_default_git_root()))).resolve()
FORMAL_MEMORY_TOP_LEVELS = {"用户记忆", "项目", "工作流", "决策", "agent"}
FORMAL_TOP_LEVEL_FILES = {"AGENTS.md", "INDEX.md", "README.md", "STRUCTURE.md"}
DELETED_OBSERVATION_PREFIX = "deleted:"
DELETED_OBSERVATION_RE = re.compile(r"^deleted:([0-9a-f]{40}):([0-9a-f]{64})$")
DELETION_OBSERVATION_LOCK = CONFIG_ROOT / "locks" / "closeout.lock"
ACTOR_SESSION_ENV_KEYS = {
    "codex": ("AGENT_MEMORY_SESSION_ID", "CODEX_THREAD_ID"),
    "claude": ("AGENT_MEMORY_SESSION_ID", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID"),
    "human": ("AGENT_MEMORY_SESSION_ID",),
    "migration": ("AGENT_MEMORY_SESSION_ID",),
    "test": ("AGENT_MEMORY_SESSION_ID",),
    "ailu": ("AGENT_MEMORY_SESSION_ID",),
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _observed_file_sha256(path: Path) -> str:
    """Avoid shadowing the public ``file_sha256`` closeout argument."""

    return file_sha256(path)


def deleted_observation_sentinel(deletion_commit: str, prior_sha256: str) -> str:
    commit = deletion_commit.strip().lower()
    digest = prior_sha256.strip().lower()
    value = f"{DELETED_OBSERVATION_PREFIX}{commit}:{digest}"
    if parse_deleted_observation(value) is None:
        raise ValueError("deleted observation requires a 40-hex commit and 64-hex prior SHA-256")
    return value


def parse_deleted_observation(value: str) -> tuple[str, str] | None:
    """Parse a deletion sentinel without consulting Git or SQLite."""

    match = DELETED_OBSERVATION_RE.fullmatch(str(value or ""))
    if match is None:
        return None
    return match.group(1), match.group(2)


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


def connect(*, read_only: bool = False) -> sqlite3.Connection:
    if not read_only:
        assert_runtime_ready("state-write")
    if not STATE_DB.exists():
        raise write_intent.IntentError(
            write_intent.STATE_SCHEMA_REASON_CODE,
            "installed state database is missing; run the installer migration",
        )
    try:
        conn = secure_sqlite_connect(
            STATE_DB,
            timeout=10,
            create=False,
            read_only=read_only,
            row_factory=sqlite3.Row,
            pragmas=("PRAGMA busy_timeout=10000",),
        )
    except OSError as exc:
        if not STATE_DB.exists():
            raise write_intent.IntentError(
                write_intent.STATE_SCHEMA_REASON_CODE,
                "installed state database is missing; run the installer migration",
            ) from exc
        raise
    try:
        # DDL belongs exclusively to the backed-up installer migration.
        # Ordinary claim writes fail closed on any schema drift.
        assert_schema_ready(conn)
    except Exception:
        conn.close()
        raise
    return conn


def assert_schema_ready(conn: sqlite3.Connection) -> None:
    """Verify claim/list state without creating or altering SQLite objects."""

    write_intent.assert_schema_ready(conn)
    required_tables = {
        "memory_session_claims",
        "memory_file_observations",
        "memory_deletion_observations",
        "memory_committed_observations",
        "memory_closeout_incidents",
    }
    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    with contextlib.closing(sqlite3.connect(":memory:")) as expected:
        ensure_schema(expected)
        required_columns = {
            table: {str(row[1]) for row in expected.execute(f"PRAGMA table_info({table})")}
            for table in required_tables
        }
        required_indexes = {
            str(row[0])
            for row in expected.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
            )
            if str(row[0]).startswith("idx_memory_session_claims_")
        }
    actual_indexes = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
        )
    }
    malformed = not required_tables.issubset(tables) or not required_indexes.issubset(actual_indexes)
    if not malformed:
        malformed = any(
            not columns.issubset(
                {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
            )
            for table, columns in required_columns.items()
        )
    if malformed:
        raise write_intent.IntentError(
            write_intent.STATE_SCHEMA_REASON_CODE,
            "installed claim schema is missing or outdated; run the installer migration",
        )


def ensure_schema(conn: sqlite3.Connection, *, commit: bool = True) -> None:
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
          intent_id TEXT NOT NULL DEFAULT '',
          target_key TEXT NOT NULL DEFAULT '',
          fencing_token INTEGER NOT NULL DEFAULT 0,
          claim_kind TEXT NOT NULL DEFAULT 'legacy',
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
          intent_id TEXT NOT NULL DEFAULT '',
          fencing_token INTEGER NOT NULL DEFAULT 0,
          git_commit TEXT NOT NULL DEFAULT '',
          observed_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_deletion_observations (
          observation_id TEXT PRIMARY KEY,
          path TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          sentinel TEXT NOT NULL,
          actor TEXT NOT NULL,
          user_authorized INTEGER NOT NULL,
          deletion_commit TEXT NOT NULL,
          parent_commit TEXT NOT NULL,
          prior_sha256 TEXT NOT NULL,
          trash_sha256 TEXT NOT NULL,
          trash_path_sha256 TEXT NOT NULL,
          evidence_ref_sha256 TEXT NOT NULL,
          evidence_ref_length INTEGER NOT NULL,
          observed_at TEXT NOT NULL,
          UNIQUE(path, deletion_commit)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_committed_observations (
          observation_id TEXT PRIMARY KEY,
          path TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          sha256 TEXT NOT NULL,
          actor TEXT NOT NULL,
          user_authorized INTEGER NOT NULL,
          intent_id TEXT NOT NULL,
          receipt_id TEXT NOT NULL,
          proposal_commit TEXT NOT NULL,
          observed_git_head TEXT NOT NULL,
          audit_chain_sha256 TEXT NOT NULL,
          evidence_ref_sha256 TEXT NOT NULL,
          evidence_ref_length INTEGER NOT NULL,
          observed_at TEXT NOT NULL,
          UNIQUE(path, intent_id, proposal_commit)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_closeout_incidents (
          incident_id TEXT PRIMARY KEY,
          intent_id TEXT NOT NULL,
          target_key TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          expected_sha256 TEXT NOT NULL,
          observed_sha256 TEXT NOT NULL DEFAULT '',
          git_commit TEXT NOT NULL,
          reason_code TEXT NOT NULL,
          detected_at TEXT NOT NULL,
          resolved_at TEXT,
          resolution_intent_id TEXT NOT NULL DEFAULT '',
          resolution_git_commit TEXT NOT NULL DEFAULT '',
          UNIQUE(intent_id, reason_code)
        )
        """
    )
    incident_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(memory_closeout_incidents)")
    }
    if "resolution_intent_id" not in incident_columns:
        conn.execute(
            "ALTER TABLE memory_closeout_incidents "
            "ADD COLUMN resolution_intent_id TEXT NOT NULL DEFAULT ''"
        )
    if "resolution_git_commit" not in incident_columns:
        conn.execute(
            "ALTER TABLE memory_closeout_incidents "
            "ADD COLUMN resolution_git_commit TEXT NOT NULL DEFAULT ''"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memory_session_claims_active "
        "ON memory_session_claims(status, actor, session_hash)"
    )
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_session_claims)")}
    if "intent_id" not in columns:
        conn.execute("ALTER TABLE memory_session_claims ADD COLUMN intent_id TEXT NOT NULL DEFAULT ''")
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_session_claims)")}
    if "target_key" not in columns:
        conn.execute("ALTER TABLE memory_session_claims ADD COLUMN target_key TEXT NOT NULL DEFAULT ''")
    if "fencing_token" not in columns:
        conn.execute("ALTER TABLE memory_session_claims ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 0")
    if "claim_kind" not in columns:
        conn.execute("ALTER TABLE memory_session_claims ADD COLUMN claim_kind TEXT NOT NULL DEFAULT 'legacy'")
    observation_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(memory_file_observations)")
    }
    if "intent_id" not in observation_columns:
        conn.execute("ALTER TABLE memory_file_observations ADD COLUMN intent_id TEXT NOT NULL DEFAULT ''")
    if "fencing_token" not in observation_columns:
        conn.execute("ALTER TABLE memory_file_observations ADD COLUMN fencing_token INTEGER NOT NULL DEFAULT 0")
    if "git_commit" not in observation_columns:
        conn.execute("ALTER TABLE memory_file_observations ADD COLUMN git_commit TEXT NOT NULL DEFAULT ''")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_session_claims_active_intent "
        "ON memory_session_claims(intent_id) WHERE intent_id<>'' AND status='active'"
    )
    # Legacy rows are deliberately allowed to remain blank until the explicit
    # v2 migrator verifies canonical-path collisions. Every v2 claim is bound
    # to a non-empty target_key and is therefore exclusive immediately.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_session_claims_active_target "
        "ON memory_session_claims(target_key) WHERE target_key<>'' AND status='active'"
    )
    write_intent.ensure_schema(conn, commit=False)
    if commit:
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


def normalize_claim_path(raw: str, *, allow_missing: bool = False) -> tuple[Path, str]:
    if allow_missing:
        target = write_intent.canonical_target(raw)
        if target.path.exists() and not target.path.is_file():
            raise ValueError(f"claim path is not a regular file: {target.path}")
        if not target.path.parent.is_dir():
            raise ValueError(f"claim parent directory does not exist: {target.path.parent}")
        return target.path, target.rel_path
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


def _is_formal_memory_markdown(rel_path: Path) -> bool:
    if rel_path.suffix.lower() != ".md":
        return False
    if len(rel_path.parts) == 1:
        return rel_path.name in FORMAL_TOP_LEVEL_FILES
    return bool(rel_path.parts) and rel_path.parts[0] in FORMAL_MEMORY_TOP_LEVELS


def _normalize_missing_formal_path(raw: str) -> tuple[Path, str, str]:
    path = Path(raw).expanduser()
    try:
        if not path.is_absolute():
            path = (Path.cwd() / path).resolve(strict=False)
        else:
            path = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError("deletion target path could not be resolved") from exc
    try:
        relative = path.relative_to(VAULT_ROOT)
    except ValueError as exc:
        raise ValueError("deletion target is outside the memory vault") from exc
    if not _is_formal_memory_markdown(relative):
        raise ValueError("deletion target is not formal vault Markdown")
    if any(character in relative.as_posix() for character in ("\0", "\n", "\r", "\t")):
        raise ValueError("deletion target contains unsupported control characters")
    if os.path.lexists(path):
        raise ValueError("deletion target still exists")
    if not path.parent.is_dir():
        raise ValueError("deletion target parent directory does not exist")
    try:
        repo_path = path.relative_to(GIT_ROOT).as_posix()
    except ValueError as exc:
        raise ValueError("memory vault is outside the configured Git root") from exc
    return path, relative.as_posix(), repo_path


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_recognized_trash_path(path: Path) -> bool:
    """Accept only platform Trash roots, never a lookalike path component."""

    home_trash = (Path.home() / ".Trash").resolve(strict=False)
    if _path_is_within(path, home_trash):
        return True

    xdg_data_home = Path(
        os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    ).expanduser().resolve(strict=False)
    if _path_is_within(path, xdg_data_home / "Trash" / "files"):
        return True

    if os.name == "nt":
        recycle_root = Path(path.anchor) / "$Recycle.Bin"
        return bool(path.anchor) and _path_is_within(path, recycle_root)

    if hasattr(os, "getuid"):
        uid = str(os.getuid())
        try:
            volume_relative = path.relative_to(Path("/Volumes"))
        except ValueError:
            volume_relative = None
        if volume_relative is not None:
            parts = volume_relative.parts
            if len(parts) >= 4 and parts[1:3] == (".Trashes", uid):
                return True
    return False


def _normalize_trash_file(raw: str) -> Path:
    lexical_path = Path(raw).expanduser()
    if not lexical_path.is_absolute():
        raise ValueError("Trash path must be absolute")
    if lexical_path.is_symlink():
        raise ValueError("Trash evidence is not an existing regular file")
    try:
        path = lexical_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Trash evidence is not an existing regular file") from exc
    if not _is_recognized_trash_path(path):
        raise ValueError("provided path is not inside a recognized Trash location")
    if not path.is_file():
        raise ValueError("Trash evidence is not an existing regular file")
    return path


def _run_git(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(GIT_ROOT), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Git validation could not be completed") from exc


def _require_clean_git_path(repo_path: str) -> None:
    result = _run_git(
        "-c",
        "core.quotepath=false",
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--",
        repo_path,
    )
    if result.returncode != 0:
        raise ValueError("target Git state could not be verified")
    if result.stdout:
        raise ValueError("deletion target has uncommitted Git index or worktree state")


def _resolved_commit(raw_commit: str) -> str:
    candidate = raw_commit.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{7,40}", candidate):
        raise ValueError("deletion commit must be a hexadecimal Git commit id")
    result = _run_git("rev-parse", "--verify", f"{candidate}^{{commit}}")
    resolved = result.stdout.decode("ascii", errors="ignore").strip().lower()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", resolved):
        raise ValueError("deletion commit cannot be resolved")
    return resolved


def _deletion_parent_and_prior_sha(deletion_commit: str, repo_path: str) -> tuple[str, str]:
    parents_result = _run_git("rev-list", "--parents", "-n", "1", deletion_commit)
    tokens = parents_result.stdout.decode("ascii", errors="ignore").strip().lower().split()
    if parents_result.returncode != 0 or not tokens or tokens[0] != deletion_commit or len(tokens) < 2:
        raise ValueError("deletion commit has no verifiable parent")

    commit_path = _run_git("cat-file", "-e", f"{deletion_commit}:{repo_path}")
    if commit_path.returncode == 0:
        raise ValueError("deletion commit still contains the target path")

    for parent_commit in tokens[1:]:
        status_result = _run_git(
            "-c",
            "core.quotepath=false",
            "diff",
            "--no-renames",
            "--name-status",
            "-z",
            parent_commit,
            deletion_commit,
            "--",
            repo_path,
        )
        status_parts = [part for part in status_result.stdout.split(b"\0") if part]
        if status_result.returncode != 0 or len(status_parts) < 2:
            continue
        if status_parts[0] != b"D" or status_parts[1].decode("utf-8", errors="strict") != repo_path:
            continue
        blob_result = _run_git("rev-parse", "--verify", f"{parent_commit}:{repo_path}")
        blob_oid = blob_result.stdout.decode("ascii", errors="ignore").strip().lower()
        if blob_result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", blob_oid):
            continue
        content_result = _run_git("cat-file", "blob", blob_oid)
        if content_result.returncode != 0:
            continue
        return parent_commit, hashlib.sha256(content_result.stdout).hexdigest()
    raise ValueError("provided commit did not delete the target relative to a parent")


def validate_deletion_observation(
    *,
    actor: str,
    target_file: str,
    trash_file: str,
    deletion_commit: str,
    evidence_ref: str,
    user_authorized: bool,
) -> dict[str, Any]:
    if actor != "human":
        raise ValueError("deletion observations are restricted to actor=human")
    if not user_authorized:
        raise ValueError("explicit user authorization flag is required")
    evidence = evidence_ref.strip()
    if not evidence:
        raise ValueError("evidence ref is required")
    if len(evidence) > 4096:
        raise ValueError("evidence ref is too long")

    target, rel_path, repo_path = _normalize_missing_formal_path(target_file)
    trash = _normalize_trash_file(trash_file)
    _require_clean_git_path(repo_path)
    resolved_commit = _resolved_commit(deletion_commit)
    ancestor = _run_git("merge-base", "--is-ancestor", resolved_commit, "HEAD")
    if ancestor.returncode == 1:
        raise ValueError("deletion commit is not an ancestor of current HEAD")
    if ancestor.returncode != 0:
        raise ValueError("deletion commit ancestry could not be verified")

    parent_commit, prior_sha256 = _deletion_parent_and_prior_sha(resolved_commit, repo_path)
    latest_result = _run_git("log", "-1", "--format=%H", "HEAD", "--", repo_path)
    latest_commit = latest_result.stdout.decode("ascii", errors="ignore").strip().lower()
    if latest_result.returncode != 0 or latest_commit != resolved_commit:
        raise ValueError("deletion commit is not the target path's latest change")
    try:
        trash_sha256 = file_sha256(trash)
    except OSError as exc:
        raise ValueError("Trash evidence could not be read") from exc
    if trash_sha256 != prior_sha256:
        raise ValueError("Trash evidence SHA-256 does not match the pre-deletion Git blob")

    evidence_sha256 = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    trash_path_sha256 = hashlib.sha256(str(trash).encode("utf-8")).hexdigest()
    sentinel = deleted_observation_sentinel(resolved_commit, prior_sha256)
    observation_material = "\0".join(
        (str(target), sentinel, trash_path_sha256, evidence_sha256, "explicit_user")
    )
    return {
        "observation_id": hashlib.sha256(observation_material.encode("utf-8")).hexdigest(),
        "path": str(target),
        "rel_path": rel_path,
        "sentinel": sentinel,
        "actor": actor,
        "user_authorized": 1,
        "deletion_commit": resolved_commit,
        "parent_commit": parent_commit,
        "prior_sha256": prior_sha256,
        "trash_sha256": trash_sha256,
        "trash_path_sha256": trash_path_sha256,
        "evidence_ref_sha256": evidence_sha256,
        "evidence_ref_length": len(evidence),
    }


@contextlib.contextmanager
def deletion_observation_lock(timeout: float = 15.0):
    DELETION_OBSERVATION_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with DELETION_OBSERVATION_LOCK.open("a+", encoding="utf-8") as handle:
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            try:
                if try_lock(handle):
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError("another memory closeout or deletion observation is still running")
            time.sleep(0.1)
        try:
            yield
        finally:
            unlock(handle)


def _store_deletion_observation(observation: dict[str, Any]) -> int:
    now = utc_now()
    audit_columns = (
        "observation_id",
        "path",
        "rel_path",
        "sentinel",
        "actor",
        "user_authorized",
        "deletion_commit",
        "parent_commit",
        "prior_sha256",
        "trash_sha256",
        "trash_path_sha256",
        "evidence_ref_sha256",
        "evidence_ref_length",
    )
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            """
            SELECT observation_id, path, rel_path, sentinel, actor, user_authorized,
                   deletion_commit, parent_commit, prior_sha256, trash_sha256,
                   trash_path_sha256, evidence_ref_sha256, evidence_ref_length
            FROM memory_deletion_observations
            WHERE path=? AND deletion_commit=?
            """,
            (observation["path"], observation["deletion_commit"]),
        ).fetchone()
        expected = tuple(observation[column] for column in audit_columns)
        if existing is not None:
            actual = tuple(existing[column] for column in audit_columns)
            if actual != expected:
                conn.rollback()
                raise ValueError("existing deletion audit record does not match this evidence")
            current = conn.execute(
                "SELECT sha256 FROM memory_file_observations WHERE path=?",
                (observation["path"],),
            ).fetchone()
            if current is not None and str(current[0]) == observation["sentinel"]:
                conn.rollback()
                return 0
        else:
            conn.execute(
                """
                INSERT INTO memory_deletion_observations (
                  observation_id, path, rel_path, sentinel, actor, user_authorized,
                  deletion_commit, parent_commit, prior_sha256, trash_sha256,
                  trash_path_sha256, evidence_ref_sha256, evidence_ref_length, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*expected, now),
            )
        conn.execute(
            """
            INSERT INTO memory_file_observations (
              path, rel_path, sha256, actor, session_hash, observed_at
            ) VALUES (?, ?, ?, ?, '', ?)
            ON CONFLICT(path) DO UPDATE SET
              rel_path=excluded.rel_path,
              sha256=excluded.sha256,
              actor=excluded.actor,
              session_hash='',
              observed_at=excluded.observed_at
            """,
            (
                observation["path"],
                observation["rel_path"],
                observation["sentinel"],
                observation["actor"],
                now,
            ),
        )
        conn.commit()
    return 1


def apply_deletion_observation(
    observation: dict[str, Any],
    *,
    actor: str,
    target_file: str,
    trash_file: str,
    deletion_commit: str,
    evidence_ref: str,
    user_authorized: bool,
) -> int:
    with deletion_observation_lock():
        refreshed = validate_deletion_observation(
            actor=actor,
            target_file=target_file,
            trash_file=trash_file,
            deletion_commit=deletion_commit,
            evidence_ref=evidence_ref,
            user_authorized=user_authorized,
        )
        if refreshed != observation:
            raise ValueError("deletion evidence changed between preview and apply")
        return _store_deletion_observation(refreshed)


def safe_deletion_observation_payload(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        key: observation[key]
        for key in (
            "rel_path",
            "sentinel",
            "actor",
            "user_authorized",
            "deletion_commit",
            "parent_commit",
            "prior_sha256",
            "trash_sha256",
            "trash_path_sha256",
            "evidence_ref_sha256",
            "evidence_ref_length",
        )
    }


def _normalize_existing_formal_path(raw: str) -> tuple[Path, str, str]:
    path, rel_path = normalize_claim_path(raw)
    if not _is_formal_memory_markdown(Path(rel_path)):
        raise ValueError("committed observation target is not formal vault Markdown")
    try:
        repo_path = path.relative_to(GIT_ROOT).as_posix()
    except ValueError as exc:
        raise ValueError("memory vault is outside the configured Git root") from exc
    return path, rel_path, repo_path


def _git_blob_digest(commit: str, repo_path: str) -> write_intent.ContentDigest:
    blob_result = _run_git("rev-parse", "--verify", f"{commit}:{repo_path}")
    blob_oid = blob_result.stdout.decode("ascii", errors="ignore").strip().lower()
    if blob_result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", blob_oid):
        raise ValueError("committed target blob could not be resolved")
    content_result = _run_git("cat-file", "blob", blob_oid)
    if content_result.returncode != 0:
        raise ValueError("committed target blob could not be read")
    return write_intent.content_hashes(content_result.stdout)


def _git_blob_sha256(commit: str, repo_path: str) -> str:
    return _git_blob_digest(commit, repo_path).raw_sha256


def _current_git_head() -> str:
    result = _run_git("rev-parse", "--verify", "HEAD^{commit}")
    head = result.stdout.decode("ascii", errors="ignore").strip().lower()
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("current Git HEAD could not be resolved")
    return head


def _committed_chain_sha256(
    intent: dict[str, Any],
    receipt: dict[str, Any],
    safety: dict[str, Any],
) -> str:
    safe_intent = dict(intent)
    snapshot = str(safe_intent.pop("proposal_canonical_snapshot", ""))
    safe_intent["proposal_canonical_snapshot_sha256"] = hashlib.sha256(snapshot.encode("utf-8")).hexdigest()
    payload = {"intent": safe_intent, "receipt": dict(receipt), "safety": dict(safety)}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_committed_observation(
    *,
    actor: str,
    target_file: str,
    intent_id: str,
    evidence_ref: str,
    user_authorized: bool,
) -> dict[str, Any]:
    """Verify an already-committed protected write from its expired intent audit chain."""

    if actor != "human":
        raise ValueError("committed observations are restricted to actor=human")
    if not user_authorized:
        raise ValueError("explicit user authorization flag is required")
    evidence = evidence_ref.strip()
    if not evidence:
        raise ValueError("evidence ref is required")
    if len(evidence) > 4096:
        raise ValueError("evidence ref is too long")
    if not re.fullmatch(r"[0-9a-f]{32}", intent_id.strip().lower()):
        raise ValueError("historical intent id is invalid")

    target, rel_path, repo_path = _normalize_existing_formal_path(target_file)
    if not write_intent.is_protected_target(target):
        raise ValueError("committed observation recovery is restricted to protected memory")
    _require_clean_git_path(repo_path)
    try:
        current_digest = write_intent.content_hashes(target.read_bytes())
    except OSError as exc:
        raise ValueError("committed observation target could not be read") from exc
    current_sha256 = current_digest.raw_sha256
    current_canonical_sha256 = current_digest.canonical_sha256
    head = _current_git_head()
    if _git_blob_digest(head, repo_path).canonical_sha256 != current_canonical_sha256:
        raise ValueError("target content does not match the current HEAD blob")

    with connect(read_only=True) as conn:
        intent_row = conn.execute(
            "SELECT * FROM memory_write_intents WHERE intent_id=?",
            (intent_id,),
        ).fetchone()
        receipt_row = conn.execute(
            "SELECT * FROM memory_write_receipts WHERE intent_id=?",
            (intent_id,),
        ).fetchone()
        safety_row = None
        if intent_row is not None:
            safety_row = conn.execute(
                "SELECT * FROM memory_safety_log WHERE id=? AND run_id=?",
                (intent_row["safety_audit_id"], intent_row["safety_run_id"]),
            ).fetchone()
        target_key = write_intent.canonical_target(target).target_key
        other_active_intents = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_write_intents "
                "WHERE target_key=? AND intent_id<>? "
                "AND status IN ('pending','approved','bound','validated')",
                (target_key, intent_id),
            ).fetchone()[0]
        )
        active_claims = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_session_claims WHERE path=? AND status='active'",
                (str(target),),
            ).fetchone()[0]
        )
    if intent_row is None or receipt_row is None or safety_row is None:
        raise ValueError("historical intent, safety audit, and terminal receipt are all required")
    if other_active_intents or active_claims:
        raise ValueError("target still has an active intent or session claim")
    intent = {key: intent_row[key] for key in intent_row.keys()}
    receipt = {key: receipt_row[key] for key in receipt_row.keys()}
    safety = {key: safety_row[key] for key in safety_row.keys()}
    proposal_commit = str(intent.get("proposal_commit", "")).lower()
    proposal_sha256 = str(intent.get("proposal_raw_sha256", "")).lower()
    receipt_id = str(receipt.get("receipt_id", "")).lower()
    original_evidence = str(intent.get("evidence_ref_sha256", "")).lower()
    historical_actor = str(intent.get("actor", ""))
    historical_session = str(intent.get("session_hash", ""))
    asserted_by = str(intent.get("asserted_by", ""))
    base_head = str(intent.get("base_git_head", "")).lower()
    validated_head = str(intent.get("validated_git_head", "")).lower()
    created_at = write_intent.parse_time(str(intent.get("created_at", "")))
    validated_at = write_intent.parse_time(str(intent.get("validated_at", "")))
    expires_at = write_intent.parse_time(str(intent.get("expires_at", "")))
    receipt_created_at = write_intent.parse_time(str(receipt.get("created_at", "")))
    safety_created_at = write_intent.parse_time(str(safety.get("created_at", "")))
    now = dt.datetime.now(dt.timezone.utc)

    exact_intent = (
        str(intent.get("target_rel_path", "")) == rel_path
        and str(intent.get("target_key", "")) == target_key
        and historical_actor in {"codex", "claude"}
        and re.fullmatch(r"[0-9a-f]{16}", historical_session) is not None
        and str(intent.get("status", "")) == "expired"
        and str(intent.get("reason_code", "")) == "INTENT_EXPIRED"
        and int(intent.get("intent_system_enabled", 0)) == 1
        and str(intent.get("effective_enforcement", "")) == "enforce"
        and str(intent.get("source_class", "")) == "user_direct"
        and str(intent.get("knowledge_kind", "")) in {"preference", "rule"}
        and str(intent.get("safety_decision", "")) == "ALLOW"
        and str(intent.get("safety_reason_code", "")) == "SOURCE_ALLOWED"
        and int(intent.get("approval_required", 1)) == 0
        and bool(asserted_by)
        and bool(str(intent.get("bound_at", "")))
        and bool(str(intent.get("validated_at", "")))
        and str(intent.get("validation_mode", "")) == "exact"
        and int(intent.get("early_commit", 0)) == 1
        and proposal_sha256 == current_sha256
        and str(intent.get("proposal_canonical_sha256", "")).lower() == current_canonical_sha256
        and str(intent.get("final_raw_sha256", "")).lower() == current_sha256
        and str(intent.get("final_canonical_sha256", "")).lower() == current_canonical_sha256
        and str(intent.get("safety_input_sha256", "")).lower() == current_sha256
        and int(intent.get("safety_input_length", 0)) > 0
        and re.fullmatch(r"[0-9a-f]{64}", original_evidence) is not None
        and re.fullmatch(r"[0-9a-f]{40}", proposal_commit) is not None
        and re.fullmatch(r"[0-9a-f]{40}", base_head) is not None
        and base_head != proposal_commit
        and re.fullmatch(r"[0-9a-f]{40}", validated_head) is not None
        and created_at is not None
        and validated_at is not None
        and expires_at is not None
        and receipt_created_at is not None
        and safety_created_at is not None
        and created_at <= safety_created_at <= validated_at <= expires_at <= receipt_created_at <= now
    )
    exact_receipt = (
        str(receipt.get("intent_id", "")) == intent_id
        and str(receipt.get("actor", "")) == historical_actor
        and str(receipt.get("session_hash", "")) == historical_session
        and str(receipt.get("target_rel_path", "")) == rel_path
        and str(receipt.get("target_key", "")) == target_key
        and str(receipt.get("outcome", "")) == "expired"
        and str(receipt.get("reason_code", "")) == "INTENT_EXPIRED"
        and str(receipt.get("detail_code", "")) == "TTL_ELAPSED"
        and str(receipt.get("validation_mode", "")) == "exact"
        and int(receipt.get("early_commit", 0)) == 1
        and str(receipt.get("proposal_commit", "")).lower() == proposal_commit
        and str(receipt.get("base_raw_sha256", "")).lower()
        == str(intent.get("base_raw_sha256", "")).lower()
        and str(receipt.get("proposal_raw_sha256", "")).lower() == current_sha256
        and str(receipt.get("proposal_canonical_sha256", "")).lower() == current_canonical_sha256
        and str(receipt.get("final_raw_sha256", "")).lower() == current_sha256
        and str(receipt.get("final_canonical_sha256", "")).lower() == current_canonical_sha256
        and str(receipt.get("source_class", "")) == "user_direct"
        and str(receipt.get("knowledge_kind", "")) in {"preference", "rule"}
        and str(receipt.get("safety_decision", "")) == "ALLOW"
        and str(receipt.get("safety_reason_code", "")) == "SOURCE_ALLOWED"
        and str(receipt.get("safety_input_sha256", "")).lower() == current_sha256
        and int(receipt.get("safety_input_length", 0)) == int(intent.get("safety_input_length", 0))
        and str(receipt.get("evidence_ref_sha256", "")).lower() == original_evidence
        and str(receipt.get("base_git_head", "")).lower() == base_head
        and str(receipt.get("validated_git_head", "")).lower() == validated_head
        and str(receipt.get("git_commit", "")) == ""
        and str(receipt.get("approval_binding_sha256", ""))
        == str(intent.get("approval_binding_sha256", ""))
        and str(receipt.get("approval_ref_sha256", ""))
        == str(intent.get("approval_ref_sha256", ""))
        and str(receipt.get("asserted_by_sha256", "")).lower()
        == hashlib.sha256(asserted_by.encode("utf-8")).hexdigest()
        and re.fullmatch(r"[0-9a-f]{32}", receipt_id) is not None
    )
    exact_safety = (
        int(safety.get("id", 0)) == int(intent.get("safety_audit_id", 0))
        and str(safety.get("run_id", "")) == str(intent.get("safety_run_id", ""))
        and str(safety.get("run_id", "")) == f"write-intent:{intent_id}"
        and str(safety.get("actor", "")) == historical_actor
        and str(safety.get("session_hash", "")) == historical_session
        and str(safety.get("trigger", "")) == "write_intent_proposal"
        and str(safety.get("decision", "")) == str(intent.get("safety_decision", "")) == "ALLOW"
        and str(safety.get("reason_code", ""))
        == str(intent.get("safety_reason_code", ""))
        == "SOURCE_ALLOWED"
        and str(safety.get("source_class", "")) == str(intent.get("source_class", ""))
        and str(safety.get("knowledge_kind", "")) == str(intent.get("knowledge_kind", ""))
        and str(safety.get("asserted_by", "")).lower()
        == hashlib.sha256(asserted_by.encode("utf-8")).hexdigest()
        and str(safety.get("input_sha256", "")).lower() == current_sha256
        and int(safety.get("input_length", 0)) == int(intent.get("safety_input_length", 0))
        and str(safety.get("evidence_ref_sha256", "")).lower()
        == hashlib.sha256(original_evidence.encode("utf-8")).hexdigest()
    )
    invalid_components = [
        name
        for name, valid in (
            ("intent", exact_intent),
            ("receipt", exact_receipt),
            ("safety", exact_safety),
        )
        if not valid
    ]
    if invalid_components:
        raise ValueError(
            "historical intent audit chain is not eligible for committed observation recovery: "
            + ",".join(invalid_components)
        )

    ancestor = _run_git("merge-base", "--is-ancestor", proposal_commit, head)
    if ancestor.returncode != 0:
        raise ValueError("historical proposal commit is not an ancestor of current HEAD")
    latest_result = _run_git("log", "-1", "--format=%H", "HEAD", "--", repo_path)
    latest_commit = latest_result.stdout.decode("ascii", errors="ignore").strip().lower()
    if latest_result.returncode != 0 or latest_commit != proposal_commit:
        raise ValueError("historical proposal commit is not the target path's latest change")
    if _git_blob_digest(proposal_commit, repo_path).canonical_sha256 != current_canonical_sha256:
        raise ValueError("historical proposal commit blob does not match the current target")
    base_ancestor = _run_git("merge-base", "--is-ancestor", base_head, proposal_commit)
    if base_ancestor.returncode != 0:
        raise ValueError("historical base does not precede the proposal commit")
    validated_ancestor = _run_git("merge-base", "--is-ancestor", proposal_commit, validated_head)
    if validated_ancestor.returncode != 0:
        raise ValueError("historical validation does not contain the proposal commit")
    current_ancestor = _run_git("merge-base", "--is-ancestor", validated_head, head)
    if current_ancestor.returncode != 0:
        raise ValueError("historical validated head is not an ancestor of current HEAD")

    evidence_sha256 = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    chain_sha256 = _committed_chain_sha256(intent, receipt, safety)
    observation_material = "\0".join(
        (str(target), current_sha256, intent_id, proposal_commit, receipt_id, evidence_sha256)
    )
    return {
        "observation_id": hashlib.sha256(observation_material.encode("utf-8")).hexdigest(),
        "path": str(target),
        "rel_path": rel_path,
        "sha256": current_sha256,
        "actor": actor,
        "user_authorized": 1,
        "intent_id": intent_id,
        "receipt_id": receipt_id,
        "proposal_commit": proposal_commit,
        "observed_git_head": head,
        "audit_chain_sha256": chain_sha256,
        "target_key": target_key,
        "canonical_sha256": current_canonical_sha256,
        "evidence_ref_sha256": evidence_sha256,
        "evidence_ref_length": len(evidence),
    }


def _store_committed_observation(observation: dict[str, Any]) -> int:
    now = utc_now()
    audit_columns = (
        "observation_id",
        "path",
        "rel_path",
        "sha256",
        "actor",
        "user_authorized",
        "intent_id",
        "receipt_id",
        "proposal_commit",
        "observed_git_head",
        "audit_chain_sha256",
        "evidence_ref_sha256",
        "evidence_ref_length",
    )
    expected = tuple(observation[column] for column in audit_columns)
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current_intent_row = conn.execute(
            "SELECT * FROM memory_write_intents WHERE intent_id=?",
            (observation["intent_id"],),
        ).fetchone()
        current_receipt_row = conn.execute(
            "SELECT * FROM memory_write_receipts WHERE intent_id=?",
            (observation["intent_id"],),
        ).fetchone()
        current_safety_row = None
        if current_intent_row is not None:
            current_safety_row = conn.execute(
                "SELECT * FROM memory_safety_log WHERE id=? AND run_id=?",
                (current_intent_row["safety_audit_id"], current_intent_row["safety_run_id"]),
            ).fetchone()
        if current_intent_row is None or current_receipt_row is None or current_safety_row is None:
            conn.rollback()
            raise ValueError("historical audit chain changed before committed observation apply")
        current_intent = {key: current_intent_row[key] for key in current_intent_row.keys()}
        current_receipt = {key: current_receipt_row[key] for key in current_receipt_row.keys()}
        current_safety = {key: current_safety_row[key] for key in current_safety_row.keys()}
        if _committed_chain_sha256(current_intent, current_receipt, current_safety) != observation["audit_chain_sha256"]:
            conn.rollback()
            raise ValueError("historical audit chain changed before committed observation apply")

        target = Path(observation["path"]).resolve()
        target_key = write_intent.canonical_target(target).target_key
        if target_key != observation["target_key"]:
            conn.rollback()
            raise ValueError("committed observation target identity changed")
        other_active_intents = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_write_intents "
                "WHERE target_key=? AND intent_id<>? "
                "AND status IN ('pending','approved','bound','validated')",
                (target_key, observation["intent_id"]),
            ).fetchone()[0]
        )
        active_claims = int(
            conn.execute(
                "SELECT COUNT(*) FROM memory_session_claims WHERE path=? AND status='active'",
                (str(target),),
            ).fetchone()[0]
        )
        if other_active_intents or active_claims:
            conn.rollback()
            raise ValueError("target gained an active intent or session claim before apply")

        try:
            repo_path = target.relative_to(GIT_ROOT).as_posix()
            _require_clean_git_path(repo_path)
            current_digest = write_intent.content_hashes(target.read_bytes())
            current_head = _current_git_head()
            latest_result = _run_git("log", "-1", "--format=%H", "HEAD", "--", repo_path)
            latest_commit = latest_result.stdout.decode("ascii", errors="ignore").strip().lower()
        except (OSError, ValueError, write_intent.IntentError) as exc:
            conn.rollback()
            raise ValueError("committed target changed before observation apply") from exc
        if (
            current_digest.raw_sha256 != observation["sha256"]
            or current_digest.canonical_sha256 != observation["canonical_sha256"]
            or current_head != observation["observed_git_head"]
            or _git_blob_digest(current_head, repo_path).canonical_sha256
            != observation["canonical_sha256"]
            or latest_result.returncode != 0
            or latest_commit != observation["proposal_commit"]
        ):
            conn.rollback()
            raise ValueError("committed target changed before observation apply")

        existing = conn.execute(
            "SELECT " + ", ".join(audit_columns) + " FROM memory_committed_observations "
            "WHERE path=? AND intent_id=? AND proposal_commit=?",
            (observation["path"], observation["intent_id"], observation["proposal_commit"]),
        ).fetchone()
        if existing is not None:
            actual = tuple(existing[column] for column in audit_columns)
            if actual != expected:
                conn.rollback()
                raise ValueError("existing committed observation does not match this audit chain")
            current = conn.execute(
                "SELECT sha256 FROM memory_file_observations WHERE path=?",
                (observation["path"],),
            ).fetchone()
            if current is not None and str(current[0]) == observation["sha256"]:
                conn.rollback()
                return 0
        else:
            conn.execute(
                "INSERT INTO memory_committed_observations ("
                + ", ".join(audit_columns)
                + ", observed_at) VALUES ("
                + ", ".join("?" for _ in audit_columns)
                + ", ?)",
                (*expected, now),
            )
        conn.execute(
            """
            INSERT INTO memory_file_observations (
              path, rel_path, sha256, actor, session_hash, observed_at
            ) VALUES (?, ?, ?, ?, '', ?)
            ON CONFLICT(path) DO UPDATE SET
              rel_path=excluded.rel_path,
              sha256=excluded.sha256,
              actor=excluded.actor,
              session_hash='',
              observed_at=excluded.observed_at
            """,
            (
                observation["path"],
                observation["rel_path"],
                observation["sha256"],
                observation["actor"],
                now,
            ),
        )
        conn.commit()
    return 1


def apply_committed_observation(
    observation: dict[str, Any],
    *,
    actor: str,
    target_file: str,
    intent_id: str,
    evidence_ref: str,
    user_authorized: bool,
) -> int:
    with deletion_observation_lock():
        refreshed = validate_committed_observation(
            actor=actor,
            target_file=target_file,
            intent_id=intent_id,
            evidence_ref=evidence_ref,
            user_authorized=user_authorized,
        )
        if refreshed != observation:
            raise ValueError("committed observation evidence changed between preview and apply")
        return _store_committed_observation(refreshed)


def safe_committed_observation_payload(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        key: observation[key]
        for key in (
            "rel_path",
            "sha256",
            "actor",
            "user_authorized",
            "intent_id",
            "receipt_id",
            "proposal_commit",
            "evidence_ref_sha256",
            "evidence_ref_length",
        )
    }


def claim_paths(actor: str, raw_session_id: str, paths: list[str], intent_id: str = "") -> list[dict[str, str]]:
    hashed = session_hash(raw_session_id)
    if not hashed:
        raise ValueError("session id is required; pass --session-id or use a supported host session environment")
    normalized = [normalize_claim_path(raw, allow_missing=bool(intent_id)) for raw in paths]
    if intent_id and len(normalized) != 1:
        raise ValueError("one write intent can bind exactly one claimed file")
    for path, rel_path in normalized:
        if (
            write_intent.ENFORCEMENT_MODE == "enforce"
            and write_intent.is_protected_target(path)
            and not intent_id
        ):
            raise ValueError(f"protected memory requires a bound write intent before editing: {rel_path}")
    now = utc_now()
    claim_bindings: dict[str, tuple[str, int, str]] = {}
    try:
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if intent_id:
                bound = write_intent.bind_claim(
                    intent_id,
                    actor=actor,
                    raw_session_id=raw_session_id,
                    claim_path=normalized[0][0],
                    claim_ref=f"{actor}:{hashed}:{normalized[0][1]}",
                    connection=conn,
                )
                if str(bound.get("target_key", "")) != write_intent.canonical_target(normalized[0][0]).target_key:
                    raise ValueError("write intent target does not match claimed file")
                claim_bindings[str(normalized[0][0])] = (
                    str(bound.get("target_key", "")),
                    int(bound.get("fencing_token") or 0),
                    "intent",
                )
            for path, rel_path in normalized:
                target = write_intent.canonical_target(path)
                target_key, fencing_token, claim_kind = claim_bindings.get(
                    str(path),
                    (target.target_key, 0, "legacy"),
                )
                if intent_id and (not target_key or fencing_token <= 0):
                    raise ValueError("bound write intent is missing a valid path fence")
                conflict = conn.execute(
                    "SELECT actor, session_hash FROM memory_session_claims "
                    "WHERE target_key=? AND status='active' AND NOT (session_hash=? AND path=?) LIMIT 1",
                    (target_key, hashed, str(path)),
                ).fetchone()
                if conflict is not None:
                    raise ValueError(f"ACTIVE_TARGET_CONFLICT: another session owns {rel_path}")
                existing = conn.execute(
                    "SELECT status, intent_id FROM memory_session_claims WHERE session_hash=? AND path=?",
                    (hashed, str(path)),
                ).fetchone()
                if (
                    existing is not None
                    and str(existing[0]) == "active"
                    and str(existing[1] or "")
                    and str(existing[1]) != intent_id
                ):
                    raise ValueError(f"active claim already has a different write intent: {rel_path}")
                conn.execute(
                    """
                    INSERT INTO memory_session_claims (
                      session_hash, actor, path, rel_path, status, claimed_at, updated_at,
                      completed_at, intent_id, target_key, fencing_token, claim_kind
                    ) VALUES (?, ?, ?, ?, 'active', ?, ?, NULL, ?, ?, ?, ?)
                    ON CONFLICT(session_hash, path) DO UPDATE SET
                      actor=excluded.actor,
                      rel_path=excluded.rel_path,
                      status='active',
                      updated_at=excluded.updated_at,
                      completed_at=NULL,
                      target_key=excluded.target_key,
                      fencing_token=excluded.fencing_token,
                      claim_kind=excluded.claim_kind,
                      intent_id=CASE
                        WHEN memory_session_claims.status='active'
                             AND memory_session_claims.intent_id<>''
                             AND excluded.intent_id=''
                        THEN memory_session_claims.intent_id
                        ELSE excluded.intent_id
                      END
                    """,
                    (
                        hashed, actor, str(path), rel_path, now, now, intent_id,
                        target_key, fencing_token, claim_kind,
                    ),
                )
            conn.commit()
    except write_intent.IntentError as exc:
        if intent_id and exc.reason_code in {"STALE_BASE", "INTENT_EXPIRED"}:
            try:
                write_intent.finalize_receipt(
                    intent_id,
                    actor=actor,
                    raw_session_id=raw_session_id,
                    outcome="expired" if exc.reason_code == "INTENT_EXPIRED" else "failed",
                    reason_code=exc.reason_code,
                    detail_code="CLAIM_BINDING_REJECTED",
                )
            except (write_intent.IntentError, OSError, sqlite3.Error):
                pass
        raise
    return [
        {
            "path": str(path),
            "rel_path": rel_path,
            "intent_id": intent_id,
            "target_key": claim_bindings.get(str(path), (write_intent.canonical_target(path).target_key, 0, "legacy"))[0],
            "fencing_token": str(claim_bindings.get(str(path), ("", 0, "legacy"))[1]),
            "claim_kind": claim_bindings.get(str(path), ("", 0, "legacy"))[2],
        }
        for path, rel_path in normalized
    ]


def active_claim_rows(
    raw_session_id: str,
    actor: str = "",
    *,
    read_only: bool = True,
    max_age_hours: float | None = None,
) -> list[dict[str, str]]:
    if max_age_hours is not None and max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    hashed = session_hash(raw_session_id)
    if not hashed:
        return []
    params: list[str] = [hashed]
    with connect(read_only=read_only) as conn:
        columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_session_claims)")}
        intent_expression = "intent_id" if "intent_id" in columns else "'' AS intent_id"
        target_expression = "target_key" if "target_key" in columns else "'' AS target_key"
        fence_expression = "fencing_token" if "fencing_token" in columns else "0 AS fencing_token"
        kind_expression = "claim_kind" if "claim_kind" in columns else "'legacy' AS claim_kind"
        query = (
            "SELECT session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
            f"{intent_expression}, {target_expression}, {fence_expression}, {kind_expression} "
            "FROM memory_session_claims "
            "WHERE session_hash=? AND status='active'"
        )
        if actor:
            query += " AND actor=?"
            params.append(actor)
        query += " ORDER BY rel_path"
        rows = conn.execute(query, params).fetchall()
    payloads = [{key: str(row[key] or "") for key in row.keys()} for row in rows]
    if max_age_hours is None:
        return payloads
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=max_age_hours)
    return [
        row
        for row in payloads
        if (parsed_time(row["updated_at"]) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) >= cutoff
    ]


def parsed_time(value: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def all_active_claim_rows(
    max_age_hours: float | None = None,
    *,
    read_only: bool = True,
) -> list[dict[str, str]]:
    if max_age_hours is not None and max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    with connect(read_only=read_only) as conn:
        columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_session_claims)")}
        intent_expression = "intent_id" if "intent_id" in columns else "'' AS intent_id"
        target_expression = "target_key" if "target_key" in columns else "'' AS target_key"
        fence_expression = "fencing_token" if "fencing_token" in columns else "0 AS fencing_token"
        kind_expression = "claim_kind" if "claim_kind" in columns else "'legacy' AS claim_kind"
        rows = conn.execute(
            "SELECT session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
            f"{intent_expression}, {target_expression}, {fence_expression}, {kind_expression} "
            "FROM memory_session_claims "
            "WHERE status='active' ORDER BY actor, session_hash, rel_path"
        ).fetchall()
    payloads = [{key: str(row[key] or "") for key in row.keys()} for row in rows]
    if max_age_hours is None:
        return payloads
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=max_age_hours)
    return [row for row in payloads if (parsed_time(row["updated_at"]) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)) >= cutoff]


def stale_active_claim_rows(max_age_hours: float = 24) -> list[dict[str, str]]:
    if max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    # Intent-backed claims are projections of a renewable path lease.  Their
    # lifetime is governed atomically by memory_write_intents.expires_at, not
    # by the claim row's updated_at timestamp.  The legacy maintenance command
    # may only age out unbound pre-v2 claims; expiring an intent projection here
    # would strand a live lease and make the active-target index inconsistent.
    rows = [
        row
        for row in all_active_claim_rows(read_only=True)
        if row.get("claim_kind") != "intent" or not row.get("intent_id")
    ]
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
                  AND (claim_kind<>'intent' OR intent_id='')
                """,
                (now, now, row["session_hash"], row["path"], row["updated_at"]),
            )
            changed += int(cursor.rowcount)
        conn.commit()
    return rows, changed


def _terminal_claim_disposition_locked(
    conn: sqlite3.Connection,
    *,
    expected_session_hash: str,
    expected_path: str,
    expected_intent_id: str,
    expected_status: str,
    expected_updated_at: str,
) -> dict[str, Any]:
    claim = conn.execute(
        "SELECT * FROM memory_session_claims WHERE session_hash=? AND path=?",
        (expected_session_hash, expected_path),
    ).fetchone()
    if claim is None:
        raise ValueError("CLAIM_DISPOSITION_NOT_FOUND")
    for key, expected in (
        ("intent_id", expected_intent_id),
        ("status", expected_status),
        ("updated_at", expected_updated_at),
    ):
        if str(claim[key] or "") != expected:
            raise ValueError("CLAIM_DISPOSITION_CAS_MISMATCH")
    if expected_status != "active" or str(claim["claim_kind"]) != "intent":
        raise ValueError("CLAIM_DISPOSITION_NOT_TERMINAL_PROJECTION")
    bound = conn.execute(
        "SELECT * FROM memory_write_intents WHERE intent_id=?",
        (expected_intent_id,),
    ).fetchone()
    receipt = conn.execute(
        "SELECT * FROM memory_write_receipts WHERE intent_id=?",
        (expected_intent_id,),
    ).fetchone()
    if bound is None or receipt is None:
        raise ValueError("CLAIM_DISPOSITION_AUDIT_CHAIN_MISSING")
    terminal = str(bound["status"])
    if terminal not in {"completed", "failed", "cancelled", "expired"}:
        raise ValueError("CLAIM_DISPOSITION_INTENT_NOT_TERMINAL")
    binding_ok = (
        str(receipt["outcome"]) == terminal
        and str(receipt["actor"]) == str(claim["actor"])
        and str(receipt["session_hash"]) == expected_session_hash
        and str(receipt["target_key"]) == str(claim["target_key"])
        and int(receipt["fencing_token"] or 0) == int(claim["fencing_token"] or 0)
        and str(bound["actor"]) == str(claim["actor"])
        and str(bound["session_hash"]) == expected_session_hash
        and str(bound["target_key"]) == str(claim["target_key"])
        and int(bound["fencing_token"] or 0) == int(claim["fencing_token"] or 0)
    )
    if not binding_ok:
        raise ValueError("CLAIM_DISPOSITION_AUDIT_CHAIN_MISMATCH")
    if terminal == "completed":
        git_commit = str(receipt["git_commit"])
        target = write_intent.canonical_target(str(bound["target_rel_path"]))
        blob = write_intent._git_blob(
            write_intent._resolve_git_commit(git_commit),
            write_intent._repo_rel_path(target),
        )
        digest = (
            write_intent.content_hashes(blob, max_bytes=write_intent.MAX_TARGET_BYTES)
            if blob is not None
            else None
        )
        if (
            digest is None
            or digest.raw_sha256 != str(bound["final_raw_sha256"])
            or digest.canonical_sha256 != str(bound["final_canonical_sha256"])
            or str(receipt["final_raw_sha256"]) != str(bound["final_raw_sha256"])
            or str(receipt["final_canonical_sha256"]) != str(bound["final_canonical_sha256"])
        ):
            raise ValueError("CLAIM_DISPOSITION_COMMIT_BLOB_MISMATCH")
    return {
        "session_hash": expected_session_hash,
        "path": expected_path,
        "rel_path": str(claim["rel_path"]),
        "intent_id": expected_intent_id,
        "claim_status": expected_status,
        "intent_status": terminal,
        "updated_at": expected_updated_at,
        "fencing_token": int(claim["fencing_token"] or 0),
        "receipt_id": str(receipt["receipt_id"]),
        "git_commit": str(receipt["git_commit"]),
    }


def terminal_claim_disposition(
    *,
    expected_session_hash: str,
    expected_path: str,
    expected_intent_id: str,
    expected_status: str,
    expected_updated_at: str,
    apply: bool = False,
) -> dict[str, Any]:
    """Preview or CAS-complete one stale terminal intent projection."""

    if not re.fullmatch(r"[0-9a-f]{16}", expected_session_hash):
        raise ValueError("CLAIM_DISPOSITION_SESSION_HASH_INVALID")
    with connect(read_only=not apply) as conn:
        if apply:
            conn.execute("BEGIN IMMEDIATE")
        try:
            preview = _terminal_claim_disposition_locked(
                conn,
                expected_session_hash=expected_session_hash,
                expected_path=expected_path,
                expected_intent_id=expected_intent_id,
                expected_status=expected_status,
                expected_updated_at=expected_updated_at,
            )
            applied = 0
            if apply:
                now = utc_now()
                cursor = conn.execute(
                    "UPDATE memory_session_claims SET status='completed', completed_at=?, updated_at=? "
                    "WHERE session_hash=? AND path=? AND intent_id=? AND status=? AND updated_at=?",
                    (
                        now,
                        now,
                        expected_session_hash,
                        expected_path,
                        expected_intent_id,
                        expected_status,
                        expected_updated_at,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ValueError("CLAIM_DISPOSITION_CAS_MISMATCH")
                conn.commit()
                applied = 1
            return {"ok": True, "preview": not apply, "applied": applied, "claim": preview}
        except Exception:
            if apply and conn.in_transaction:
                conn.rollback()
            raise


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


def _normalize_closeout_item(item: dict[str, Any], default_git_commit: str) -> dict[str, Any]:
    intent_id = str(item.get("intent_id", "")).strip()
    fencing_token = item.get("fencing_token")
    if not intent_id:
        raise write_intent.IntentError("INTENT_NOT_FOUND", "closeout item requires intent_id")
    if not isinstance(fencing_token, int) or isinstance(fencing_token, bool) or fencing_token <= 0:
        raise write_intent.IntentError("LEASE_FENCED", "a positive fencing token is required")
    supplied_sha256 = str(item.get("file_sha256", "")).strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", supplied_sha256) is None:
        raise write_intent.IntentError("FILE_SHA256_INVALID", "file_sha256 must be a lowercase SHA-256")
    canonical = write_intent.canonical_target(str(item.get("target", "")))
    target_path = canonical.path.resolve()
    if canonical.rel_path != str(item.get("rel_path", "")):
        raise write_intent.IntentError("CLAIM_PATH_MISMATCH", "rel_path does not match the canonical target")
    requested_commit = str(item.get("git_commit", "") or default_git_commit).strip()
    if not requested_commit:
        raise write_intent.IntentError("GIT_COMMIT_INVALID", "closeout item requires git_commit")
    return {
        "intent_id": intent_id,
        "fencing_token": fencing_token,
        "canonical": canonical,
        "target_path": target_path,
        "file_sha256": supplied_sha256,
        "git_commit": requested_commit,
        "detail_code": str(item.get("detail_code", "")),
        "reason_code": str(item.get("reason_code", "WRITE_COMPLETED")),
    }


def finalize_closeout_batch(
    items: list[dict[str, Any]],
    *,
    actor: str,
    raw_session_id: str,
    git_commit: str = "",
) -> dict[str, Any]:
    """Finalize every item in one all-or-nothing state transaction."""

    hashed = session_hash(raw_session_id)
    if not hashed:
        raise write_intent.IntentError("SESSION_REQUIRED", "session id is required")
    if not items or len(items) > 100:
        raise write_intent.IntentError("CLOSEOUT_BATCH_INVALID", "closeout batch must contain 1 to 100 items")
    normalized = [_normalize_closeout_item(item, git_commit) for item in items]
    intent_ids = [str(item["intent_id"]) for item in normalized]
    target_keys = [str(item["canonical"].target_key) for item in normalized]
    if len(intent_ids) != len(set(intent_ids)) or len(target_keys) != len(set(target_keys)):
        raise write_intent.IntentError("CLOSEOUT_BATCH_DUPLICATE", "closeout batch contains duplicate intents or targets")

    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        prepared: list[dict[str, Any]] = []
        try:
            # Phase 1: verify every item and every audit-chain endpoint before
            # the first receipt, observation, or claim is mutated.
            for item in normalized:
                intent_id = str(item["intent_id"])
                fencing_token = int(item["fencing_token"])
                canonical = item["canonical"]
                target_path = item["target_path"]
                supplied_sha256 = str(item["file_sha256"])
                if not target_path.is_file() or _observed_file_sha256(target_path) != supplied_sha256:
                    raise write_intent.IntentError(
                        "OBSERVATION_CONTENT_CHANGED",
                        "target bytes changed before batch closeout",
                    )
                intent_row = conn.execute(
                    "SELECT * FROM memory_write_intents WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()
                if intent_row is None:
                    raise write_intent.IntentError("INTENT_NOT_FOUND", f"write intent not found: {intent_id}")
                if str(intent_row["actor"]) != actor or str(intent_row["session_hash"]) != hashed:
                    raise write_intent.IntentError(
                        "INTENT_SESSION_MISMATCH",
                        "intent belongs to a different actor or session",
                    )
                if (
                    str(intent_row["target_key"]) != canonical.target_key
                    or int(intent_row["fencing_token"] or 0) != fencing_token
                ):
                    raise write_intent.IntentError("LEASE_FENCED", "intent target fence does not match closeout")
                resolved_commit = write_intent._resolve_git_commit(str(item["git_commit"]))
                blob = write_intent._git_blob(
                    resolved_commit,
                    write_intent._repo_rel_path(canonical),
                )
                committed_digest = (
                    write_intent.content_hashes(blob, max_bytes=write_intent.MAX_TARGET_BYTES)
                    if blob is not None
                    else None
                )
                if (
                    committed_digest is None
                    or supplied_sha256 != str(intent_row["final_raw_sha256"])
                    or committed_digest.raw_sha256 != str(intent_row["final_raw_sha256"])
                    or committed_digest.canonical_sha256 != str(intent_row["final_canonical_sha256"])
                ):
                    raise write_intent.IntentError(
                        "COMMIT_BLOB_MISMATCH",
                        "committed target blob does not match validated final content",
                    )

                existing_receipt = conn.execute(
                    "SELECT * FROM memory_write_receipts WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()
                if existing_receipt is not None:
                    observation = conn.execute(
                        "SELECT sha256, actor, session_hash, intent_id, fencing_token, git_commit "
                        "FROM memory_file_observations WHERE path=?",
                        (str(target_path),),
                    ).fetchone()
                    completed_claim = conn.execute(
                        "SELECT status FROM memory_session_claims "
                        "WHERE session_hash=? AND actor=? AND path=? AND intent_id=? "
                        "AND target_key=? AND fencing_token=?",
                        (hashed, actor, str(target_path), intent_id, canonical.target_key, fencing_token),
                    ).fetchone()
                    if not (
                        str(existing_receipt["outcome"]) == "completed"
                        and int(existing_receipt["fencing_token"] or 0) == fencing_token
                        and str(existing_receipt["git_commit"]) == resolved_commit
                        and observation is not None
                        and str(observation["sha256"]) == supplied_sha256
                        and str(observation["actor"]) == actor
                        and str(observation["session_hash"]) == hashed
                        and str(observation["intent_id"]) == intent_id
                        and int(observation["fencing_token"] or 0) == fencing_token
                        and str(observation["git_commit"]) == resolved_commit
                        and completed_claim is not None
                        and str(completed_claim["status"]) == "completed"
                    ):
                        raise write_intent.IntentError(
                            "CLOSEOUT_TERMINAL_MISMATCH",
                            "terminal closeout state does not match the requested audit chain",
                        )
                else:
                    write_intent.assert_current_lease(
                        intent_id,
                        actor=actor,
                        raw_session_id=raw_session_id,
                        fencing_token=fencing_token,
                        target=target_path,
                        require_unexpired=True,
                        connection=conn,
                    )
                    if str(intent_row["status"]) != "validated":
                        raise write_intent.IntentError(
                            "INTENT_NOT_VALIDATED",
                            "a successful receipt requires a validated intent",
                        )
                    claim = conn.execute(
                        "SELECT status, intent_id, target_key, fencing_token FROM memory_session_claims "
                        "WHERE session_hash=? AND actor=? AND path=?",
                        (hashed, actor, str(target_path)),
                    ).fetchone()
                    if claim is None or str(claim["status"]) != "active":
                        raise write_intent.IntentError("CLAIM_NOT_ACTIVE", "closeout requires the exact active claim")
                    if (
                        str(claim["intent_id"]) != intent_id
                        or str(claim["target_key"]) != canonical.target_key
                        or int(claim["fencing_token"] or 0) != fencing_token
                    ):
                        raise write_intent.IntentError(
                            "CLAIM_BINDING_MISMATCH",
                            "active claim does not project the current intent lease",
                        )
                prepared.append({**item, "existing_receipt": existing_receipt, "resolved_commit": resolved_commit})

            # Re-read all bytes after full validation and immediately before the
            # first state mutation, so no earlier item can hide a later drift.
            for item in prepared:
                target_path = item["target_path"]
                if not target_path.is_file() or _observed_file_sha256(target_path) != str(item["file_sha256"]):
                    raise write_intent.IntentError(
                        "OBSERVATION_CONTENT_CHANGED",
                        "target bytes changed during batch validation",
                    )

            results: list[dict[str, Any]] = []
            observed = 0
            completed = 0
            resolved_incidents = 0
            now = utc_now()
            for item in prepared:
                canonical = item["canonical"]
                target_path = item["target_path"]
                intent_id = str(item["intent_id"])
                fencing_token = int(item["fencing_token"])
                existing_receipt = item["existing_receipt"]
                if existing_receipt is not None:
                    receipt = {key: existing_receipt[key] for key in existing_receipt.keys()}
                    receipt["idempotent"] = True
                    receipt["requested_outcome_mismatch"] = False
                    results.append({
                        "receipt": receipt,
                        "observed": 0,
                        "completed": 0,
                        "idempotent": True,
                        "fencing_token": fencing_token,
                        "target_key": canonical.target_key,
                    })
                    continue
                receipt = write_intent.finalize_receipt(
                    intent_id,
                    actor=actor,
                    raw_session_id=raw_session_id,
                    outcome="completed",
                    reason_code=str(item["reason_code"]),
                    git_commit=str(item["resolved_commit"]),
                    detail_code=str(item["detail_code"]),
                    fencing_token=fencing_token,
                    connection=conn,
                    commit=False,
                )
                observation_cursor = conn.execute(
                    """
                    INSERT INTO memory_file_observations (
                      path, rel_path, sha256, actor, session_hash,
                      intent_id, fencing_token, git_commit, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                      rel_path=excluded.rel_path, sha256=excluded.sha256,
                      actor=excluded.actor, session_hash=excluded.session_hash,
                      intent_id=excluded.intent_id, fencing_token=excluded.fencing_token,
                      git_commit=excluded.git_commit, observed_at=excluded.observed_at
                    WHERE memory_file_observations.fencing_token <= excluded.fencing_token
                    """,
                    (
                        str(target_path), canonical.rel_path, str(item["file_sha256"]), actor,
                        hashed, intent_id, fencing_token, str(receipt["git_commit"]), now,
                    ),
                )
                if observation_cursor.rowcount != 1:
                    raise write_intent.IntentError(
                        "OBSERVATION_FENCED",
                        "a newer path fence already owns the file observation",
                    )
                claim_cursor = conn.execute(
                    "UPDATE memory_session_claims SET status='completed', completed_at=?, updated_at=? "
                    "WHERE session_hash=? AND actor=? AND path=? AND status='active' "
                    "AND intent_id=? AND target_key=? AND fencing_token=?",
                    (
                        now, now, hashed, actor, str(target_path), intent_id,
                        canonical.target_key, fencing_token,
                    ),
                )
                if claim_cursor.rowcount != 1:
                    raise write_intent.IntentError(
                        "CLAIM_STATE_CHANGED",
                        "claim changed while closeout was being finalized",
                    )
                # An unresolved post-finalize drift can only be cleared by a
                # newer, exact ADOPT of the same canonical target. Phase 1 has
                # already proven that current raw bytes, validated final raw,
                # and the committed Git blob are identical. Keep resolution in
                # this same transaction as the new receipt/observation/claim;
                # there is intentionally no naked manual-resolve API.
                intent_row = conn.execute(
                    "SELECT reconcile_action FROM memory_write_intents WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()
                item_resolved = 0
                if intent_row is not None and str(intent_row["reconcile_action"]).upper() == "ADOPT":
                    resolution_cursor = conn.execute(
                        "UPDATE memory_closeout_incidents SET resolved_at=?, "
                        "resolution_intent_id=?, resolution_git_commit=? "
                        "WHERE target_key=? AND resolved_at IS NULL",
                        (
                            now,
                            intent_id,
                            str(receipt["git_commit"]),
                            canonical.target_key,
                        ),
                    )
                    item_resolved = int(resolution_cursor.rowcount)
                    resolved_incidents += item_resolved
                observed += 1
                completed += 1
                results.append({
                    "receipt": receipt,
                    "observed": 1,
                    "completed": 1,
                    "idempotent": False,
                    "fencing_token": fencing_token,
                    "target_key": canonical.target_key,
                    "resolved_incidents": item_resolved,
                })
            conn.commit()
            incidents: list[dict[str, str]] = []
            # The receipt is immutable once committed. A same-user filesystem
            # writer can still race immediately after that commit, so detect and
            # durably record the post-commit drift for Doctor/Stop to fail closed.
            for item in prepared:
                target_path = item["target_path"]
                expected_sha256 = str(item["file_sha256"])
                observed_sha256 = ""
                if target_path.is_file():
                    try:
                        observed_sha256 = _observed_file_sha256(target_path)
                    except OSError:
                        observed_sha256 = ""
                if observed_sha256 == expected_sha256:
                    continue
                incident_id = hashlib.sha256(
                    f"closeout-drift:{item['intent_id']}:{expected_sha256}".encode("utf-8")
                ).hexdigest()[:32]
                incident = {
                    "incident_id": incident_id,
                    "intent_id": str(item["intent_id"]),
                    "target_key": str(item["canonical"].target_key),
                    "rel_path": str(item["canonical"].rel_path),
                    "expected_sha256": expected_sha256,
                    "observed_sha256": observed_sha256,
                    "git_commit": str(item["resolved_commit"]),
                    "reason_code": "POST_FINALIZE_CONTENT_DRIFT",
                    "detected_at": utc_now(),
                }
                with connect() as incident_conn:
                    incident_conn.execute(
                        "INSERT OR IGNORE INTO memory_closeout_incidents ("
                        "incident_id, intent_id, target_key, rel_path, expected_sha256, "
                        "observed_sha256, git_commit, reason_code, detected_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        tuple(incident[key] for key in (
                            "incident_id", "intent_id", "target_key", "rel_path",
                            "expected_sha256", "observed_sha256", "git_commit",
                            "reason_code", "detected_at",
                        )),
                    )
                    incident_conn.commit()
                incidents.append(incident)
            return {
                "items": results,
                "receipts": [item["receipt"] for item in results],
                "observed": observed,
                "completed": completed,
                "count": len(results),
                "idempotent": all(bool(item["idempotent"]) for item in results),
                "incidents": incidents,
                "resolved_incidents": resolved_incidents,
                "ok": not incidents,
            }
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise


def finalize_closeout_transaction(
    *,
    intent_id: str,
    actor: str,
    raw_session_id: str,
    fencing_token: int,
    target: str | Path,
    git_commit: str,
    file_sha256: str,
    rel_path: str,
    detail_code: str = "",
    reason_code: str = "WRITE_COMPLETED",
) -> dict[str, Any]:
    """Backward-compatible one-item wrapper over the atomic batch API."""

    payload = finalize_closeout_batch(
        [{
            "intent_id": intent_id,
            "fencing_token": fencing_token,
            "target": str(target),
            "git_commit": git_commit,
            "file_sha256": file_sha256,
            "rel_path": rel_path,
            "detail_code": detail_code,
            "reason_code": reason_code,
        }],
        actor=actor,
        raw_session_id=raw_session_id,
    )
    return dict(payload["items"][0])


def _enrich_claim_lease_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    current = dt.datetime.now(dt.timezone.utc)
    enriched: list[dict[str, Any]] = []
    with connect(read_only=True) as conn:
        for row in rows:
            payload: dict[str, Any] = dict(row)
            intent_id = str(row.get("intent_id", ""))
            if not intent_id:
                payload["lease_state"] = "legacy"
                payload["blocks_stop"] = True
                enriched.append(payload)
                continue
            bound = conn.execute(
                "SELECT actor, session_hash, target_key, fencing_token, status, expires_at "
                "FROM memory_write_intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            if bound is None:
                payload["lease_state"] = "intent_missing"
                payload["blocks_stop"] = True
                enriched.append(payload)
                continue
            status = str(bound["status"])
            payload["intent_status"] = status
            payload["expires_at"] = str(bound["expires_at"])
            if status not in write_intent.ACTIVE_STATUSES:
                payload["lease_state"] = "intent_terminal"
            elif (
                str(bound["actor"]) != str(row["actor"])
                or str(bound["session_hash"]) != str(row["session_hash"])
                or str(bound["target_key"]) != str(row.get("target_key", ""))
                or int(bound["fencing_token"] or 0) != int(row.get("fencing_token") or 0)
            ):
                payload["lease_state"] = "claim_binding_mismatch"
            else:
                expiry = write_intent.parse_time(str(bound["expires_at"]))
                if expiry is not None and expiry <= current:
                    payload["lease_state"] = "lease_expired"
                else:
                    latest = conn.execute(
                        "SELECT last_fence FROM memory_path_fences WHERE target_key=?",
                        (str(bound["target_key"]),),
                    ).fetchone()
                    payload["lease_state"] = (
                        "live"
                        if latest is not None
                        and int(latest[0]) == int(bound["fencing_token"] or 0)
                        else "lease_fenced"
                    )
            payload["blocks_stop"] = payload["lease_state"] != "live"
            enriched.append(payload)
    return enriched


def active_claim_lease_rows(raw_session_id: str, actor: str = "") -> list[dict[str, Any]]:
    """Return this session's active claims with read-only intent/fence health."""

    return _enrich_claim_lease_rows(active_claim_rows(raw_session_id, actor, read_only=True))


def all_active_claim_lease_rows() -> list[dict[str, Any]]:
    """Return all active claims with health derivable without raw session ids."""

    return _enrich_claim_lease_rows(all_active_claim_rows(read_only=True))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Track per-session ownership of shared memory files.")
    parser.add_argument(
        "--actor",
        choices=("codex", "claude", "human", "migration", "test", "ailu"),
        default="codex",
    )
    parser.add_argument("--session-id", default="")
    parser.add_argument("--json", action="store_true")
    subparsers = parser.add_subparsers(dest="action", required=True)
    claim_parser = subparsers.add_parser("claim", help="Claim one or more Markdown files for this session.")
    claim_parser.add_argument("--file", action="append", required=True)
    claim_parser.add_argument("--intent-id", default="", help="Bind this single-file claim to a prepared write intent.")
    subparsers.add_parser("list", help="List active claims for this session.")
    subparsers.add_parser("list-all", help="List all active claims.")
    expire_parser = subparsers.add_parser("expire-stale", help="Preview or expire abandoned active claims.")
    expire_parser.add_argument("--older-than-hours", type=float, default=24)
    expire_parser.add_argument("--apply", action="store_true", help="Mark matching claims expired; default is preview only.")
    deletion_parser = subparsers.add_parser(
        "observe-deletion",
        help="Preview or record an explicitly authorized, recoverable historical Markdown deletion.",
    )
    deletion_parser.add_argument("--file", required=True, help="Missing formal Markdown path inside the vault.")
    deletion_parser.add_argument("--trash-path", required=True, help="Existing recoverable copy in a Trash location.")
    deletion_parser.add_argument("--deletion-commit", required=True, help="Git commit that deleted the target path.")
    deletion_parser.add_argument("--evidence-ref", required=True, help="Authorization evidence; only its hash is stored.")
    deletion_parser.add_argument(
        "--confirm-user-authorized",
        action="store_true",
        help="Confirm that the user explicitly authorized this exact deletion.",
    )
    deletion_parser.add_argument("--apply", action="store_true", help="Write the audit and tombstone; default is preview only.")
    committed_parser = subparsers.add_parser(
        "observe-committed",
        help="Preview or record an already-committed protected write from an expired exact intent.",
    )
    committed_parser.add_argument("--file", required=True, help="Existing formal Markdown path inside the vault.")
    committed_parser.add_argument("--intent-id", required=True, help="Expired historical intent with an exact audit chain.")
    committed_parser.add_argument("--evidence-ref", required=True, help="Recovery evidence; only its hash is stored.")
    committed_parser.add_argument(
        "--confirm-user-authorized",
        action="store_true",
        help="Confirm that the historical write was explicitly authorized by the user.",
    )
    committed_parser.add_argument("--apply", action="store_true", help="Write the audit and observation; default is preview only.")
    return parser.parse_args()


def enforce_low_level_cli_policy(actor: str, action: str) -> None:
    if actor in write_intent.CANONICAL_WRITER_ACTORS and action not in {"list", "list-all"}:
        raise ValueError(
            "LOW_LEVEL_GATEWAY_MUTATION_FORBIDDEN: automatic writers must use the high-level write gateway"
        )


def main() -> int:
    args = parse_args()
    raw_session_id = session_value(args.session_id, args.actor)
    applied = 0
    observation: dict[str, Any] | None = None
    observation_kind = ""
    try:
        assert_runtime_ready("claim")
        enforce_low_level_cli_policy(args.actor, args.action)
        if args.action == "claim":
            rows = claim_paths(args.actor, raw_session_id, args.file, args.intent_id)
        elif args.action == "list-all":
            rows = all_active_claim_rows(read_only=True)
        elif args.action == "expire-stale":
            rows, applied = expire_stale_claims(args.older_than_hours, args.apply)
        elif args.action == "observe-deletion":
            observation_kind = "deletion"
            observation = validate_deletion_observation(
                actor=args.actor,
                target_file=args.file,
                trash_file=args.trash_path,
                deletion_commit=args.deletion_commit,
                evidence_ref=args.evidence_ref,
                user_authorized=args.confirm_user_authorized,
            )
            applied = (
                apply_deletion_observation(
                    observation,
                    actor=args.actor,
                    target_file=args.file,
                    trash_file=args.trash_path,
                    deletion_commit=args.deletion_commit,
                    evidence_ref=args.evidence_ref,
                    user_authorized=args.confirm_user_authorized,
                )
                if args.apply
                else 0
            )
            rows = []
        elif args.action == "observe-committed":
            observation_kind = "committed"
            observation = validate_committed_observation(
                actor=args.actor,
                target_file=args.file,
                intent_id=args.intent_id,
                evidence_ref=args.evidence_ref,
                user_authorized=args.confirm_user_authorized,
            )
            applied = (
                apply_committed_observation(
                    observation,
                    actor=args.actor,
                    target_file=args.file,
                    intent_id=args.intent_id,
                    evidence_ref=args.evidence_ref,
                    user_authorized=args.confirm_user_authorized,
                )
                if args.apply
                else 0
            )
            rows = []
        else:
            if not raw_session_id:
                raise ValueError("session id is required; pass --session-id or use a supported host session environment")
            rows = active_claim_rows(raw_session_id, args.actor, read_only=True)
    except (ValueError, OSError, sqlite3.Error) as exc:
        reason_code = getattr(exc, "reason_code", "CLAIM_ERROR")
        payload: dict[str, Any] = {
            "ok": False,
            "reason_code": reason_code,
            "error": str(exc),
            "action": args.action,
            "degraded": reason_code == write_intent.STATE_SCHEMA_REASON_CODE,
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"claim_error={reason_code} {exc}")
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
    if observation is not None:
        payload["preview"] = not args.apply
        payload["observation"] = (
            safe_committed_observation_payload(observation)
            if observation_kind == "committed"
            else safe_deletion_observation_payload(observation)
        )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if observation is not None:
            safe = (
                safe_committed_observation_payload(observation)
                if observation_kind == "committed"
                else safe_deletion_observation_payload(observation)
            )
            print(
                f"{observation_kind}_observation=ok applied={applied} preview={not args.apply} "
                f"actor={args.actor} rel_path={safe['rel_path']}"
            )
            if observation_kind == "deletion":
                print(f"sentinel={safe['sentinel']}")
        else:
            print(f"claims={len(rows)} applied={applied} actor={args.actor} session={payload['session_hash']}")
            for row in rows:
                print(row.get("rel_path", row.get("path", "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
