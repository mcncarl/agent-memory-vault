#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_memory_env import env_value


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"
STATE_DB = Path(
    os.path.expandvars(env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite"))
).expanduser().resolve()
DEFAULT_COLLECTION_PATH = Path(
    os.path.expandvars(
        env_value("VECTOR_DIR", "$HOME/.config/agent-memory/zvec/memory_chunks_embeddinggemma_768")
    )
).expanduser().resolve()
DEFAULT_LOCK_PATH = Path(
    os.path.expandvars(env_value("ZVEC_LOCK", "$HOME/.config/agent-memory/locks/zvec.lock"))
).expanduser().resolve()
DEFAULT_MODEL = env_value("EMBEDDING_MODEL", "google/embeddinggemma-300m")
DEFAULT_EMBEDDING_DIM = int(env_value("EMBEDDING_DIM", "768"))
DEFAULT_DEVICE = env_value("EMBEDDING_DEVICE", "cpu")
DEFAULT_LIMIT = 5
CHUNK_MAX_CHARS = 1400
CHUNK_OVERLAP_CHARS = 160
CHUNK_POLICY_VERSION = "2"
HISTORY_SECTION_PATTERNS = ("已过时", "历史信息", "旧方案", "废弃", "不再使用")
EXCLUDED_MEMORY_TYPES = {"directory_index", "routing", "template", "agent_case_candidate", "skill_candidate"}
EXCLUDED_STATUS = {"archived", "deleted", "draft", "obsolete", "outdated", "deprecated", "stale"}


@dataclass
class IndexedDoc:
    path: Path
    rel_path: str
    sha256: str
    title: str
    memory_type: str
    track: str
    project_id: str
    app_id: str
    agent_id: str
    status: str
    sensitivity: str
    verified_at: str


@dataclass
class Chunk:
    chunk_id: str
    path: Path
    rel_path: str
    doc_sha256: str
    chunk_sha256: str
    chunk_index: int
    title: str
    chunk_text: str
    memory_type: str
    track: str
    project_id: str
    agent_id: str
    app_id: str
    verified_at: str


class EmbedderError(RuntimeError):
    pass


def load_sqlite_index() -> Any:
    path = SCRIPT_ROOT / "agent_memory_index.py"
    spec = importlib.util.spec_from_file_location("agent_memory_index_module", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot_load_sqlite_index {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_memory_index_module"] = module
    spec.loader.exec_module(module)
    return module


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


@contextlib.contextmanager
def zvec_lock(exclusive: bool, timeout: float):
    DEFAULT_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DEFAULT_LOCK_PATH.open("a+", encoding="utf-8") as handle:
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + max(timeout, 0.0)
        while True:
            try:
                fcntl.flock(handle.fileno(), operation | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"zvec lock timed out: {DEFAULT_LOCK_PATH}")
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def strip_frontmatter(text: str) -> str:
    if not text.startswith("---\n"):
        return text
    end = text.find("\n---", 4)
    if end == -1:
        return text
    return text[end + 4 :].lstrip()


def section_text(text: str, heading_patterns: list[str]) -> str:
    lines = strip_frontmatter(text).splitlines()
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
    return normalize_text("\n".join(captured))


def compact_excerpt(text: str, limit: int = 220) -> str:
    text = normalize_text(text)
    return text[:limit] + ("..." if len(text) > limit else "")


def current_fact_lines(text: str) -> list[str]:
    lines: list[str] = []
    skipping = False
    skip_level = 7
    for raw_line in strip_frontmatter(text).splitlines():
        heading_match = re.match(r"^(#{1,6})\s+(.+?)\s*$", raw_line)
        if heading_match:
            level = len(heading_match.group(1))
            heading = heading_match.group(2)
            if skipping and level <= skip_level:
                skipping = False
            if any(pattern in heading for pattern in HISTORY_SECTION_PATTERNS):
                skipping = True
                skip_level = level
                continue
        if not skipping:
            lines.append(raw_line)
    return lines


def chunk_body(text: str, max_chars: int = CHUNK_MAX_CHARS, overlap: int = CHUNK_OVERLAP_CHARS) -> list[str]:
    paragraphs = [line.strip() for line in current_fact_lines(text)]
    paragraphs = [line for line in paragraphs if line and not line.startswith("---")]
    chunks: list[str] = []
    current = ""

    def flush() -> None:
        nonlocal current
        item = normalize_text(current)
        if item:
            chunks.append(item)
        current = ""

    for paragraph in paragraphs:
        if len(paragraph) > max_chars:
            flush()
            start = 0
            while start < len(paragraph):
                end = min(len(paragraph), start + max_chars)
                chunks.append(paragraph[start:end].strip())
                if end == len(paragraph):
                    break
                start = max(end - overlap, start + 1)
            continue
        candidate = f"{current}\n{paragraph}".strip() if current else paragraph
        if len(candidate) > max_chars:
            flush()
            current = paragraph
        else:
            current = candidate
    flush()
    return chunks


def stable_chunk_id(rel_path: str, doc_sha: str, chunk_index: int, chunk_sha: str) -> str:
    return sha256_text(f"{rel_path}\n{doc_sha}\n{chunk_index}\n{chunk_sha}")


def build_chunks(sqlite_index: Any, doc: IndexedDoc) -> list[Chunk]:
    text = doc.path.read_text(encoding="utf-8", errors="replace")
    meta = sqlite_index.parse_frontmatter(text)
    keywords = sqlite_index.as_text(meta.get("keywords"))
    summary = section_text(text, ["当前有效摘要"])
    base_lines = [
        f"Title: {doc.title}",
        f"Path: {doc.rel_path}",
        f"Type: {doc.memory_type} / {doc.track}",
    ]
    if doc.project_id:
        base_lines.append(f"Project: {doc.project_id}")
    if keywords:
        base_lines.append(f"Keywords: {keywords}")
    if summary:
        base_lines.append(f"Summary: {summary}")

    raw_chunks = [normalize_text("\n".join(base_lines))]
    for body_chunk in chunk_body(text):
        value = f"Title: {doc.title}\nPath: {doc.rel_path}\n{body_chunk}"
        if body_chunk and value not in raw_chunks:
            raw_chunks.append(value)

    chunks: list[Chunk] = []
    for index, raw_chunk in enumerate(raw_chunks):
        clean_text = normalize_text(raw_chunk)
        if not clean_text:
            continue
        chunk_sha = sha256_text(clean_text)
        chunks.append(
            Chunk(
                chunk_id=stable_chunk_id(doc.rel_path, doc.sha256, index, chunk_sha),
                path=doc.path,
                rel_path=doc.rel_path,
                doc_sha256=doc.sha256,
                chunk_sha256=chunk_sha,
                chunk_index=index,
                title=doc.title,
                chunk_text=clean_text,
                memory_type=doc.memory_type,
                track=doc.track,
                project_id=doc.project_id,
                agent_id=doc.agent_id,
                app_id=doc.app_id,
                verified_at=doc.verified_at,
            )
        )
    return chunks


def connect(state_db: Path = STATE_DB) -> sqlite3.Connection:
    state_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(state_db)
    conn.row_factory = sqlite3.Row
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

        CREATE TABLE IF NOT EXISTS memory_vector_chunks (
          chunk_id TEXT PRIMARY KEY,
          path TEXT NOT NULL,
          rel_path TEXT NOT NULL,
          doc_sha256 TEXT NOT NULL,
          chunk_sha256 TEXT NOT NULL,
          chunk_index INTEGER NOT NULL,
          title TEXT,
          chunk_text TEXT,
          memory_type TEXT NOT NULL,
          track TEXT NOT NULL,
          project_id TEXT,
          agent_id TEXT,
          app_id TEXT,
          verified_at TEXT,
          embedding_model TEXT NOT NULL,
          embedding_dim INTEGER NOT NULL,
          indexed_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_memory_vector_chunks_path
          ON memory_vector_chunks(path);

        CREATE INDEX IF NOT EXISTS idx_memory_vector_chunks_scope
          ON memory_vector_chunks(track, memory_type, project_id, agent_id, app_id);

        CREATE TABLE IF NOT EXISTS memory_vector_index_state (
          path TEXT PRIMARY KEY,
          rel_path TEXT,
          doc_sha256 TEXT,
          status TEXT NOT NULL,
          chunk_count INTEGER DEFAULT 0,
          last_error TEXT DEFAULT '',
          embedding_model TEXT,
          embedding_dim INTEGER,
          chunk_policy_version TEXT DEFAULT '1',
          updated_at TEXT NOT NULL
        );
        """
    )
    ensure_column(conn, "memory_vector_index_state", "chunk_policy_version", "TEXT DEFAULT '1'")
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("memory_vector_schema_version", "2"))
    conn.commit()


def doc_from_row(row: sqlite3.Row) -> IndexedDoc:
    return IndexedDoc(
        path=Path(row["path"]),
        rel_path=str(row["rel_path"]),
        sha256=str(row["sha256"]),
        title=str(row["title"]),
        memory_type=str(row["memory_type"]),
        track=str(row["track"]),
        project_id=str(row["project_id"] or ""),
        app_id=str(row["app_id"] or "codex"),
        agent_id=str(row["agent_id"] or "codex"),
        status=str(row["status"] or "active"),
        sensitivity=str(row["sensitivity"] or "normal"),
        verified_at=str(row["verified_at"] or ""),
    )


def is_eligible_doc(doc: IndexedDoc, vault_root: Path) -> bool:
    if not doc.path.exists() or doc.path.suffix.lower() != ".md":
        return False
    if doc.path.name == "README.md" or doc.path.name.startswith("_模板"):
        return False
    if doc.memory_type in EXCLUDED_MEMORY_TYPES:
        return False
    if doc.status in EXCLUDED_STATUS:
        return False
    if doc.sensitivity.lower() in {"secret", "credential"}:
        return False
    try:
        doc.path.relative_to(vault_root)
    except ValueError:
        return False
    return True


def load_index_docs(conn: sqlite3.Connection, vault_root: Path) -> list[IndexedDoc]:
    rows = conn.execute(
        """
        SELECT path, rel_path, sha256, title, memory_type, track, project_id,
               app_id, agent_id, status, sensitivity, verified_at
        FROM memory_docs
        ORDER BY rel_path
        """
    ).fetchall()
    return [doc for doc in (doc_from_row(row) for row in rows) if is_eligible_doc(doc, vault_root)]


def load_changed_docs(conn: sqlite3.Connection, raw_paths: list[str], vault_root: Path) -> tuple[list[IndexedDoc], list[str]]:
    docs: list[IndexedDoc] = []
    errors: list[str] = []
    for raw_path in raw_paths:
        path = Path(os.path.expandvars(raw_path)).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        path = path.resolve()
        row = conn.execute(
            """
            SELECT path, rel_path, sha256, title, memory_type, track, project_id,
                   app_id, agent_id, status, sensitivity, verified_at
            FROM memory_docs
            WHERE path=?
            """,
            (str(path),),
        ).fetchone()
        if not row:
            errors.append(f"not_in_sqlite_index {path}")
            continue
        doc = doc_from_row(row)
        if not is_eligible_doc(doc, vault_root):
            mark_state(conn, doc, "skipped", 0, "not_eligible")
            continue
        docs.append(doc)
    return docs, errors


class EmbeddingGemmaEmbedder:
    def __init__(self, model_name: str, embedding_dim: int, device: str = "cpu", cache_folder: str = "") -> None:
        self.model_name = model_name
        self.embedding_dim = embedding_dim
        self.device = device
        self.cache_folder = cache_folder
        self._model: Any | None = None

    def _load_model(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import-not-found]
        except ImportError as exc:
            raise EmbedderError(
                "embedding_dependencies_missing; install optional packages: "
                "python3 -m pip install zvec sentence-transformers torch"
            ) from exc
        kwargs: dict[str, object] = {}
        if self.device:
            kwargs["device"] = self.device
        if self.cache_folder:
            kwargs["cache_folder"] = self.cache_folder
        try:
            self._model = SentenceTransformer(self.model_name, **kwargs)
        except Exception as exc:
            detail = re.sub(r"\s+", " ", str(exc)).strip()[:700]
            raise EmbedderError(
                f"embedding_model_load_failed model={self.model_name}; "
                "if using a gated model, accept its license and authenticate with Hugging Face; "
                f"detail={detail}"
            ) from exc
        return self._model

    def _normalize_vectors(self, raw: Any, expected_count: int) -> list[list[float]]:
        try:
            import numpy as np  # type: ignore[import-not-found]
        except ImportError as exc:
            raise EmbedderError("numpy_missing") from exc
        array = np.asarray(raw, dtype="float32")
        if array.ndim == 1:
            array = array.reshape(1, -1)
        if array.ndim != 2:
            raise EmbedderError(f"bad_vector_shape shape={array.shape}")
        if array.shape[0] != expected_count:
            raise EmbedderError(f"embedding_count_mismatch expected={expected_count} actual={array.shape[0]}")
        if array.shape[1] < self.embedding_dim:
            raise EmbedderError(f"embedding_dim_mismatch expected={self.embedding_dim} actual={array.shape[1]}")
        if array.shape[1] > self.embedding_dim:
            array = array[:, : self.embedding_dim]
        normalized: list[list[float]] = []
        for row in array:
            vector = [float(item) for item in row.tolist()]
            norm = math.sqrt(sum(item * item for item in vector))
            if norm > 0:
                vector = [item / norm for item in vector]
            normalized.append(vector)
        return normalized

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        model = self._load_model()
        try:
            if hasattr(model, "encode_document"):
                raw = model.encode_document(texts, show_progress_bar=False)
            else:
                raw = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        except Exception as exc:
            raise EmbedderError(f"document_encode_failed {exc}") from exc
        return self._normalize_vectors(raw, len(texts))

    def embed_query(self, query: str) -> list[float]:
        model = self._load_model()
        try:
            if hasattr(model, "encode_query"):
                raw = model.encode_query(query, show_progress_bar=False)
            else:
                raw = model.encode([query], normalize_embeddings=True, show_progress_bar=False)
        except Exception as exc:
            raise EmbedderError(f"query_encode_failed {exc}") from exc
        return self._normalize_vectors(raw, 1)[0]


class ZvecStore:
    def __init__(self, collection_path: Path, embedding_dim: int) -> None:
        self.collection_path = collection_path
        self.embedding_dim = embedding_dim
        self._zvec: Any | None = None
        self._collection: Any | None = None

    def _load_zvec(self) -> Any:
        if self._zvec is not None:
            return self._zvec
        try:
            import zvec  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("zvec_not_installed; install optional package: python3 -m pip install zvec") from exc
        self._zvec = zvec
        return zvec

    def _schema(self) -> Any:
        zvec = self._load_zvec()
        return zvec.CollectionSchema(
            name="memory_chunks",
            fields=[
                zvec.FieldSchema(name="path", data_type=zvec.DataType.STRING),
                zvec.FieldSchema(name="rel_path", data_type=zvec.DataType.STRING),
                zvec.FieldSchema(name="title", data_type=zvec.DataType.STRING),
                zvec.FieldSchema(name="chunk_index", data_type=zvec.DataType.INT32),
                zvec.FieldSchema(name="memory_type", data_type=zvec.DataType.STRING),
                zvec.FieldSchema(name="track", data_type=zvec.DataType.STRING),
                zvec.FieldSchema(name="project_id", data_type=zvec.DataType.STRING),
                zvec.FieldSchema(name="agent_id", data_type=zvec.DataType.STRING),
                zvec.FieldSchema(name="app_id", data_type=zvec.DataType.STRING),
                zvec.FieldSchema(name="verified_at", data_type=zvec.DataType.STRING),
            ],
            vectors=[
                zvec.VectorSchema(
                    name="embedding",
                    data_type=zvec.DataType.VECTOR_FP32,
                    dimension=self.embedding_dim,
                    index_param=zvec.HnswIndexParam(metric_type=zvec.MetricType.COSINE),
                )
            ],
        )

    def init(self) -> None:
        if self._collection is not None:
            return
        zvec = self._load_zvec()
        self.collection_path.parent.mkdir(parents=True, exist_ok=True)
        if self.collection_path.exists():
            self._collection = zvec.open(path=str(self.collection_path))
        else:
            self._collection = zvec.create_and_open(path=str(self.collection_path), schema=self._schema())

    @property
    def collection(self) -> Any:
        self.init()
        return self._collection

    def replace_chunks(self, chunks: list[Chunk], embeddings: list[list[float]], old_chunk_ids: list[str]) -> None:
        zvec = self._load_zvec()
        if old_chunk_ids:
            self.collection.delete(ids=old_chunk_ids)
        for chunk, embedding in zip(chunks, embeddings, strict=True):
            self.collection.insert(
                zvec.Doc(
                    id=chunk.chunk_id,
                    vectors={"embedding": embedding},
                    fields={
                        "path": str(chunk.path),
                        "rel_path": chunk.rel_path,
                        "title": chunk.title,
                        "chunk_index": int(chunk.chunk_index),
                        "memory_type": chunk.memory_type,
                        "track": chunk.track,
                        "project_id": chunk.project_id,
                        "agent_id": chunk.agent_id,
                        "app_id": chunk.app_id,
                        "verified_at": chunk.verified_at,
                    },
                )
            )
        try:
            self.collection.optimize()
        except Exception:
            pass

    def search(self, embedding: list[float], limit: int) -> list[tuple[str, float]]:
        zvec = self._load_zvec()
        results = self.collection.query(queries=zvec.Query(field_name="embedding", vector=embedding), topk=max(limit, 1))
        return [(str(item.id), float(item.score)) for item in results]


def old_chunk_ids(conn: sqlite3.Connection, path: Path) -> list[str]:
    return [
        str(row[0])
        for row in conn.execute(
            "SELECT chunk_id FROM memory_vector_chunks WHERE path=? ORDER BY chunk_index",
            (str(path),),
        ).fetchall()
    ]


def mark_state(
    conn: sqlite3.Connection,
    doc: IndexedDoc,
    status: str,
    chunk_count: int,
    error: str = "",
    model: str = DEFAULT_MODEL,
    dim: int = DEFAULT_EMBEDDING_DIM,
) -> None:
    conn.execute(
        """
        INSERT INTO memory_vector_index_state (
          path, rel_path, doc_sha256, status, chunk_count, last_error,
          embedding_model, embedding_dim, chunk_policy_version, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
          rel_path=excluded.rel_path,
          doc_sha256=excluded.doc_sha256,
          status=excluded.status,
          chunk_count=excluded.chunk_count,
          last_error=excluded.last_error,
          embedding_model=excluded.embedding_model,
          embedding_dim=excluded.embedding_dim,
          chunk_policy_version=excluded.chunk_policy_version,
          updated_at=excluded.updated_at
        """,
        (str(doc.path), doc.rel_path, doc.sha256, status, chunk_count, error[:800], model, dim, CHUNK_POLICY_VERSION, utc_now()),
    )


def upsert_chunks(conn: sqlite3.Connection, chunks: list[Chunk], model: str, dim: int) -> None:
    indexed_at = utc_now()
    conn.executemany(
        """
        INSERT INTO memory_vector_chunks (
          chunk_id, path, rel_path, doc_sha256, chunk_sha256, chunk_index,
          title, chunk_text, memory_type, track, project_id, agent_id, app_id,
          verified_at, embedding_model, embedding_dim, indexed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                chunk.chunk_id,
                str(chunk.path),
                chunk.rel_path,
                chunk.doc_sha256,
                chunk.chunk_sha256,
                chunk.chunk_index,
                chunk.title,
                chunk.chunk_text,
                chunk.memory_type,
                chunk.track,
                chunk.project_id,
                chunk.agent_id,
                chunk.app_id,
                chunk.verified_at,
                model,
                dim,
                indexed_at,
            )
            for chunk in chunks
        ],
    )


def refresh_doc(
    sqlite_index: Any,
    conn: sqlite3.Connection,
    store: ZvecStore,
    embedder: EmbeddingGemmaEmbedder,
    doc: IndexedDoc,
    model: str,
    dim: int,
    force: bool = False,
) -> tuple[str, int, str]:
    current = conn.execute(
        "SELECT doc_sha256, status, embedding_model, embedding_dim, chunk_policy_version FROM memory_vector_index_state WHERE path=?",
        (str(doc.path),),
    ).fetchone()
    if (
        current
        and not force
        and current["doc_sha256"] == doc.sha256
        and current["status"] == "indexed"
        and current["embedding_model"] == model
        and int(current["embedding_dim"] or 0) == dim
        and str(current["chunk_policy_version"] or "1") == CHUNK_POLICY_VERSION
    ):
        return ("unchanged", 0, "")

    chunks = build_chunks(sqlite_index, doc)
    if not chunks:
        ids = old_chunk_ids(conn, doc.path)
        if ids:
            store.replace_chunks([], [], ids)
        conn.execute("DELETE FROM memory_vector_chunks WHERE path=?", (str(doc.path),))
        mark_state(conn, doc, "skipped", 0, "empty_doc", model, dim)
        return ("skipped", 0, "empty_doc")

    try:
        embeddings = embedder.embed_documents([chunk.chunk_text for chunk in chunks])
        actual_dim = len(embeddings[0])
        if actual_dim != dim:
            raise EmbedderError(f"embedding_dim_mismatch expected={dim} actual={actual_dim}")
        ids = old_chunk_ids(conn, doc.path)
        store.replace_chunks(chunks, embeddings, ids)
        conn.execute("DELETE FROM memory_vector_chunks WHERE path=?", (str(doc.path),))
        upsert_chunks(conn, chunks, model, dim)
        mark_state(conn, doc, "indexed", len(chunks), "", model, dim)
        return ("indexed", len(chunks), "")
    except Exception as exc:
        mark_state(conn, doc, "error", len(chunks), str(exc), model, dim)
        return ("error", 0, str(exc))


def lexical_terms(query: str) -> set[str]:
    terms = {item.lower() for item in re.split(r"\s+", query.strip()) if len(item.strip()) >= 2}
    terms.update(item.lower() for item in re.findall(r"[A-Za-z0-9_./+-]{2,}", query))
    for cjk in re.findall(r"[\u4e00-\u9fff]{2,}", query):
        if len(cjk) <= 6:
            terms.add(cjk)
        for size in (2, 3):
            for index in range(0, max(len(cjk) - size + 1, 0)):
                terms.add(cjk[index : index + size])
    return terms


def rank_adjustment(row: sqlite3.Row, query_terms: set[str]) -> float:
    if not query_terms:
        return 0.0
    text = f"{row['title'] or ''}\n{row['rel_path'] or ''}\n{row['chunk_text'] or ''}".lower()
    matches = [term for term in query_terms if term in text]
    adjustment = min(len(matches) * 0.03, 0.18)
    if any(term in str(row["title"] or "").lower() or term in str(row["rel_path"] or "").lower() for term in query_terms):
        adjustment += 0.05
    return adjustment


def vector_rows(conn: sqlite3.Connection, scored_ids: list[tuple[str, float]], query: str = "") -> list[dict[str, object]]:
    if not scored_ids:
        return []
    by_id = {chunk_id: score for chunk_id, score in scored_ids}
    placeholders = ",".join("?" for _ in by_id)
    rows = conn.execute(
        f"""
        SELECT chunk_id, path, rel_path, title, chunk_index, chunk_text,
               memory_type, track, project_id, agent_id, app_id, verified_at,
               embedding_model, embedding_dim, indexed_at
        FROM memory_vector_chunks
        WHERE chunk_id IN ({placeholders})
        """,
        tuple(by_id),
    ).fetchall()
    query_terms = lexical_terms(query)
    mapped: list[dict[str, object]] = []
    for row in rows:
        vector_score = by_id[row["chunk_id"]]
        rank_score = vector_score - rank_adjustment(row, query_terms)
        mapped.append(
            {
                "chunk_id": row["chunk_id"],
                "score": rank_score,
                "vector_score": vector_score,
                "path": row["path"],
                "rel_path": row["rel_path"],
                "title": row["title"],
                "chunk_index": row["chunk_index"],
                "summary": compact_excerpt(row["chunk_text"]),
                "memory_type": row["memory_type"],
                "track": row["track"],
                "project_id": row["project_id"],
                "agent_id": row["agent_id"],
                "app_id": row["app_id"],
                "verified_at": row["verified_at"],
                "embedding_model": row["embedding_model"],
                "embedding_dim": row["embedding_dim"],
                "indexed_at": row["indexed_at"],
            }
        )
    best_by_path: dict[str, dict[str, object]] = {}
    for item in mapped:
        path = str(item["path"])
        previous = best_by_path.get(path)
        if previous is None or float(item["score"]) < float(previous["score"]):
            best_by_path[path] = item
    deduped = list(best_by_path.values())
    deduped.sort(key=lambda item: float(item["score"]))
    return deduped


def parity_report(conn: sqlite3.Connection, vault_root: Path) -> dict[str, object]:
    eligible_docs = load_index_docs(conn, vault_root)
    eligible = {str(doc.path): doc.rel_path for doc in eligible_docs}
    rows = conn.execute("SELECT path, rel_path, status, chunk_count, last_error FROM memory_vector_index_state").fetchall()
    indexed = {str(row["path"]): row for row in rows if row["status"] == "indexed" and str(row["path"]) in eligible}
    all_state_paths = {str(row["path"]) for row in rows}
    missing = sorted(eligible[path] for path in eligible.keys() - indexed.keys())
    stale = sorted(all_state_paths - eligible.keys())
    errors = [
        {"rel_path": str(row["rel_path"] or row["path"]), "error": str(row["last_error"] or "")[:300]}
        for row in rows if row["status"] == "error"
    ]
    chunk_count = int(conn.execute("SELECT COUNT(*) FROM memory_vector_chunks").fetchone()[0])
    return {
        "eligible_docs": len(eligible), "indexed_docs": len(indexed), "chunk_count": chunk_count,
        "missing_docs": missing, "stale_paths": stale, "errors": errors,
        "parity_ok": not missing and not stale and not errors,
    }


def prune_ineligible(conn: sqlite3.Connection, store: ZvecStore, vault_root: Path) -> tuple[int, int, list[str]]:
    eligible_paths = {str(doc.path) for doc in load_index_docs(conn, vault_root)}
    rows = conn.execute("SELECT path FROM memory_vector_index_state UNION SELECT path FROM memory_vector_chunks").fetchall()
    stale_paths = sorted(str(row[0]) for row in rows if str(row[0]) not in eligible_paths)
    deleted_chunks = 0
    errors: list[str] = []
    for raw_path in stale_paths:
        ids = old_chunk_ids(conn, Path(raw_path))
        try:
            if ids:
                store.replace_chunks([], [], ids)
            conn.execute("DELETE FROM memory_vector_chunks WHERE path=?", (raw_path,))
            conn.execute("DELETE FROM memory_vector_index_state WHERE path=?", (raw_path,))
            deleted_chunks += len(ids)
        except Exception as exc:
            errors.append(f"{raw_path}: {exc}")
    return len(stale_paths), deleted_chunks, errors


def print_scan_result(result: dict[str, object], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(f"vector_index={result['status']}")
    print(f"docs_seen={result['docs_seen']}")
    print(f"docs_indexed={result['docs_indexed']}")
    print(f"docs_unchanged={result['docs_unchanged']}")
    print(f"docs_skipped={result['docs_skipped']}")
    print(f"docs_error={result['docs_error']}")
    print(f"chunks_indexed={result['chunks_indexed']}")
    if result.get("errors"):
        for item in result["errors"]:  # type: ignore[index]
            print(f"error: {item}")


def print_search_result(query: str, rows: list[dict[str, object]], as_json: bool) -> None:
    result = {"query": query, "results": rows}
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(f"query={query}")
    print(f"results={len(rows)}")
    for index, row in enumerate(rows, 1):
        print(f"{index}. {row['rel_path']}")
        print(f"   title: {row['title']}")
        print(f"   chunk_index: {row['chunk_index']} score={row['score']} vector_score={row.get('vector_score', row['score'])}")
        print(f"   type: {row['memory_type']} track={row['track']} project_id={row['project_id']}")
        print(f"   verified_at: {row['verified_at']}")
        print(f"   summary: {row['summary']}")
        print(f"   path: {row['path']}")


def run_indexing(args: argparse.Namespace, sqlite_index: Any, conn: sqlite3.Connection, store: ZvecStore) -> int:
    init_db(conn)
    store.init()
    sqlite_index.init_db(conn)
    vault_root = Path(sqlite_index.VAULT_ROOT)
    docs: list[IndexedDoc] = []
    errors: list[str] = []
    if args.scan:
        docs.extend(load_index_docs(conn, vault_root))
    if args.changed_file:
        changed_docs, changed_errors = load_changed_docs(conn, args.changed_file, vault_root)
        docs.extend(changed_docs)
        errors.extend(changed_errors)

    deduped: dict[str, IndexedDoc] = {str(doc.path): doc for doc in docs}
    embedder = EmbeddingGemmaEmbedder(args.model, args.embedding_dim, args.device, args.cache_folder)
    stats = {
        "status": "ok",
        "docs_seen": len(deduped),
        "docs_indexed": 0,
        "docs_unchanged": 0,
        "docs_skipped": 0,
        "docs_error": 0,
        "chunks_indexed": 0,
        "pruned_docs": 0,
        "pruned_chunks": 0,
        "errors": errors,
    }
    if args.prune:
        pruned_docs, pruned_chunks, prune_errors = prune_ineligible(conn, store, vault_root)
        stats["pruned_docs"] = pruned_docs
        stats["pruned_chunks"] = pruned_chunks
        errors.extend(prune_errors)
    if deduped:
        try:
            preflight = embedder.embed_query("embedding preflight")
            if len(preflight) != args.embedding_dim:
                raise EmbedderError(f"embedding_dim_mismatch expected={args.embedding_dim} actual={len(preflight)}")
        except Exception as exc:
            stats["status"] = "error"
            stats["errors"] = [str(exc)]
            print_scan_result(stats, args.json)
            return 2
    for doc in deduped.values():
        status, count, detail = refresh_doc(sqlite_index, conn, store, embedder, doc, args.model, args.embedding_dim, args.force)
        if status == "indexed":
            stats["docs_indexed"] = int(stats["docs_indexed"]) + 1
            stats["chunks_indexed"] = int(stats["chunks_indexed"]) + count
        elif status == "unchanged":
            stats["docs_unchanged"] = int(stats["docs_unchanged"]) + 1
        elif status == "skipped":
            stats["docs_skipped"] = int(stats["docs_skipped"]) + 1
        else:
            stats["docs_error"] = int(stats["docs_error"]) + 1
            cast_errors = stats["errors"]
            if isinstance(cast_errors, list):
                cast_errors.append(f"{doc.rel_path}: {detail}")
    if stats["errors"]:
        stats["status"] = "partial_error" if int(stats["docs_indexed"]) or int(stats["docs_unchanged"]) else "error"
    stats["parity"] = parity_report(conn, vault_root)
    print_scan_result(stats, args.json)
    return 0 if not stats["errors"] else 2


def run_search(args: argparse.Namespace, conn: sqlite3.Connection, store: ZvecStore) -> int:
    init_db(conn)
    store.init()
    embedder = EmbeddingGemmaEmbedder(args.model, args.embedding_dim, args.device, args.cache_folder)
    try:
        query_embedding = embedder.embed_query(args.search)
    except Exception as exc:
        payload = {"query": args.search, "error": str(exc), "results": []}
        print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else f"query={args.search}\nerror: {exc}")
        return 2
    scored_ids = store.search(query_embedding, max(args.limit * 12, args.limit))
    rows = vector_rows(conn, scored_ids, args.search)[: max(args.limit, 1)]
    print_search_result(args.search, rows, args.json)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and query the optional Zvec semantic index for Codex memory.")
    parser.add_argument("--init", action="store_true", help="Create SQLite vector tables and Zvec collection.")
    parser.add_argument("--scan", action="store_true", help="Incrementally index eligible Markdown docs from the SQLite memory index.")
    parser.add_argument("--prune", action="store_true", help="Remove deleted, renamed, or no-longer-eligible vector rows.")
    parser.add_argument("--report", action="store_true", help="Report Markdown/SQLite/Zvec parity without embedding work.")
    parser.add_argument("--changed-file", action="append", default=[], help="Refresh one changed Markdown file. Repeatable.")
    parser.add_argument("--search", help="Semantic search query.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Maximum search results.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Embedding model name or local path.")
    parser.add_argument("--device", default=DEFAULT_DEVICE, help="Device for SentenceTransformer, default: cpu.")
    parser.add_argument("--cache-folder", default="", help="Optional Hugging Face/SentenceTransformers cache folder.")
    parser.add_argument("--embedding-dim", type=int, default=DEFAULT_EMBEDDING_DIM, help="Expected embedding dimension.")
    parser.add_argument("--state-db", default=str(STATE_DB), help=argparse.SUPPRESS)
    parser.add_argument("--collection-path", default=str(DEFAULT_COLLECTION_PATH), help=argparse.SUPPRESS)
    parser.add_argument("--force", action="store_true", help="Re-index even when doc hashes are unchanged.")
    parser.add_argument("--lock-timeout", type=float, default=60.0, help="Seconds to wait for concurrent Zvec readers or writers.")
    return parser.parse_args()


def run_locked(args: argparse.Namespace) -> int:
    sqlite_index = load_sqlite_index()
    state_db = Path(args.state_db).expanduser().resolve()
    collection_path = Path(args.collection_path).expanduser().resolve()
    store = ZvecStore(collection_path, args.embedding_dim)
    try:
        with connect(state_db) as conn:
            init_db(conn)
            if args.init:
                store.init()
                if not (args.scan or args.prune or args.report or args.changed_file or args.search):
                    payload = {
                        "status": "ok",
                        "state_db": str(state_db),
                        "zvec_collection": str(collection_path),
                        "embedding_model": args.model,
                        "embedding_dim": args.embedding_dim,
                        "embedding_backend": "sentence-transformers",
                    }
                    print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else "\n".join(f"{k}={v}" for k, v in payload.items()))
            exit_code = 0
            if args.scan or args.prune or args.changed_file:
                exit_code = max(exit_code, run_indexing(args, sqlite_index, conn, store))
            if args.report:
                report = parity_report(conn, Path(sqlite_index.VAULT_ROOT))
                print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else "\n".join(f"{k}={v}" for k, v in report.items()))
            if args.search:
                exit_code = max(exit_code, run_search(args, conn, store))
            return exit_code
    except Exception as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2))
        else:
            print(f"vector_index=error\nerror: {exc}", file=sys.stderr)
        return 2


def main() -> int:
    args = parse_args()
    if not (args.init or args.scan or args.prune or args.report or args.changed_file or args.search):
        args.init = True
    exclusive = bool(args.init or args.scan or args.prune or args.changed_file)
    try:
        with zvec_lock(exclusive=exclusive, timeout=args.lock_timeout):
            return run_locked(args)
    except TimeoutError as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2))
        else:
            print(f"vector_index=error\nerror: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
