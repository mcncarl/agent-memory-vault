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

from agent_memory_env import env_value, expand_path
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
    "yichen-content-studio": ("AGENT_MEMORY_SESSION_ID",),
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    conn = secure_sqlite_connect(
        STATE_DB,
        timeout=10,
        create=not read_only,
        read_only=read_only,
        row_factory=sqlite3.Row,
        pragmas=("PRAGMA busy_timeout=10000",),
    )
    if not read_only:
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
          intent_id TEXT NOT NULL DEFAULT '',
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
        "CREATE INDEX IF NOT EXISTS idx_memory_session_claims_active "
        "ON memory_session_claims(status, actor, session_hash)"
    )
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_session_claims)")}
    if "intent_id" not in columns:
        conn.execute("ALTER TABLE memory_session_claims ADD COLUMN intent_id TEXT NOT NULL DEFAULT ''")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_session_claims_active_intent "
        "ON memory_session_claims(intent_id) WHERE intent_id<>'' AND status='active'"
    )
    write_intent.ensure_schema(conn)
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
            write_intent.PROTECTED_PATHS
            and write_intent.ENFORCEMENT_MODE == "enforce"
            and write_intent.is_protected_target(path)
            and not intent_id
        ):
            raise ValueError(f"protected memory requires a bound write intent before editing: {rel_path}")
    now = utc_now()
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
            for path, rel_path in normalized:
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
                      session_hash, actor, path, rel_path, status, claimed_at, updated_at, completed_at, intent_id
                    ) VALUES (?, ?, ?, ?, 'active', ?, ?, NULL, ?)
                    ON CONFLICT(session_hash, path) DO UPDATE SET
                      actor=excluded.actor,
                      rel_path=excluded.rel_path,
                      status='active',
                      updated_at=excluded.updated_at,
                      completed_at=NULL,
                      intent_id=CASE
                        WHEN memory_session_claims.status='active'
                             AND memory_session_claims.intent_id<>''
                             AND excluded.intent_id=''
                        THEN memory_session_claims.intent_id
                        ELSE excluded.intent_id
                      END
                    """,
                    (hashed, actor, str(path), rel_path, now, now, intent_id),
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
    return [{"path": str(path), "rel_path": rel_path, "intent_id": intent_id} for path, rel_path in normalized]


def active_claim_rows(
    raw_session_id: str,
    actor: str = "",
    *,
    read_only: bool = False,
    max_age_hours: float | None = None,
) -> list[dict[str, str]]:
    if max_age_hours is not None and max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    hashed = session_hash(raw_session_id)
    if not hashed:
        return []
    params: list[str] = [hashed]
    try:
        with connect(read_only=read_only) as conn:
            columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_session_claims)")}
            if not columns:
                return []
            intent_expression = "intent_id" if "intent_id" in columns else "'' AS intent_id"
            query = (
                "SELECT session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                f"{intent_expression} FROM memory_session_claims "
                "WHERE session_hash=? AND status='active'"
            )
            if actor:
                query += " AND actor=?"
                params.append(actor)
            query += " ORDER BY rel_path"
            rows = conn.execute(query, params).fetchall()
    except (OSError, sqlite3.Error):
        if read_only and not STATE_DB.exists():
            return []
        raise
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
    read_only: bool = False,
) -> list[dict[str, str]]:
    if max_age_hours is not None and max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    try:
        with connect(read_only=read_only) as conn:
            columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(memory_session_claims)")}
            if not columns:
                return []
            intent_expression = "intent_id" if "intent_id" in columns else "'' AS intent_id"
            rows = conn.execute(
                "SELECT session_hash, actor, path, rel_path, status, claimed_at, updated_at, "
                f"{intent_expression} FROM memory_session_claims "
                "WHERE status='active' ORDER BY actor, session_hash, rel_path"
            ).fetchall()
    except (OSError, sqlite3.Error):
        if read_only and not STATE_DB.exists():
            return []
        raise
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
    parser.add_argument(
        "--actor",
        choices=("codex", "claude", "human", "migration", "test", "yichen-content-studio"),
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


def main() -> int:
    args = parse_args()
    raw_session_id = session_value(args.session_id, args.actor)
    applied = 0
    observation: dict[str, Any] | None = None
    observation_kind = ""
    try:
        if args.action == "claim":
            rows = claim_paths(args.actor, raw_session_id, args.file, args.intent_id)
        elif args.action == "list-all":
            rows = all_active_claim_rows()
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
            rows = active_claim_rows(raw_session_id, args.actor)
    except (ValueError, OSError, sqlite3.Error) as exc:
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
