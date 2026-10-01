from __future__ import annotations

import contextlib
import io
import json
import math
import sqlite3
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_index as memory_index
import agent_memory_zvec_index as zvec


def indexed_doc(path: Path, memory_id: str) -> zvec.IndexedDoc:
    return zvec.IndexedDoc(
        path=path,
        rel_path=f"工作流/{path.name}",
        sha256="b" * 64,
        title=path.stem,
        memory_type="workflow",
        track="workflow",
        project_id="global",
        app_id="agent-memory",
        agent_id="codex",
        status="active",
        sensitivity="normal",
        verified_at="2026-08-25",
        memory_id=memory_id,
    )


def insert_memory_doc(
    conn: sqlite3.Connection,
    path: Path,
    memory_id: str,
    *,
    fact_status: str | None,
) -> None:
    path = path.resolve()
    rel_path = f"工作流/{path.name}"
    conn.execute(
        """
        INSERT INTO memory_docs(
          path,rel_path,memory_id,sha256,title,memory_type,track,project_id,
          app_id,agent_id,status,sensitivity,verified_at,mtime,size_bytes,
          line_count,indexed_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            str(path), rel_path, memory_id, "b" * 64, path.stem, "workflow",
            "workflow", "global", "agent-memory", "codex", "active",
            "normal", "2026-08-25", path.stat().st_mtime,
            path.stat().st_size, 1, "now",
        ),
    )
    if fact_status is not None:
        conn.execute(
            """
            INSERT INTO memory_fact_states(
              rel_path,fact_key,fact_status,current_rel_path,indexed_at
            ) VALUES(?,?,?,?,?)
            """,
            (rel_path, f"fact:{path.stem}", fact_status, rel_path, "now"),
        )


class ZvecIdentityAndMigrationTests(unittest.TestCase):
    def test_changed_noncurrent_fact_is_intentionally_excluded_without_state(self) -> None:
        noncurrent_statuses = (
            "superseded",
            "conflict",
            "historical",
            "expired",
            "not_yet_valid",
            "no_current",
            "invalid_metadata",
            "invalid_relation",
        )
        for fact_status in noncurrent_statuses:
            with self.subTest(fact_status=fact_status), tempfile.TemporaryDirectory() as raw_root:
                root = Path(raw_root).resolve()
                path = root / f"{fact_status}.md"
                path.write_text("# historical fact\n", encoding="utf-8")
                conn = sqlite3.connect(":memory:")
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                zvec.init_db(conn)
                insert_memory_doc(conn, path, "a" * 64, fact_status=fact_status)

                docs, errors = zvec.load_changed_docs(conn, [str(path)], root)
                state_count = int(
                    conn.execute("SELECT COUNT(*) FROM memory_vector_index_state").fetchone()[0]
                )
                parity = zvec.parity_report(conn, root)
                conn.close()

                self.assertEqual(docs, [])
                self.assertEqual(errors, [])
                self.assertEqual(state_count, 0)
                self.assertTrue(parity["parity_ok"], parity)

    def test_changed_current_or_nonfact_document_remains_eligible(self) -> None:
        for fact_status in (None, "current"):
            with self.subTest(fact_status=fact_status), tempfile.TemporaryDirectory() as raw_root:
                root = Path(raw_root).resolve()
                path = root / "current.md"
                path.write_text("# current fact\n", encoding="utf-8")
                conn = sqlite3.connect(":memory:")
                conn.row_factory = sqlite3.Row
                memory_index.init_db(conn)
                zvec.init_db(conn)
                insert_memory_doc(conn, path, "a" * 64, fact_status=fact_status)

                docs, errors = zvec.load_changed_docs(conn, [str(path)], root)
                conn.close()

                self.assertEqual(errors, [])
                self.assertEqual([doc.rel_path for doc in docs], ["工作流/current.md"])

    def test_changed_file_truly_missing_from_sqlite_still_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            path = root / "missing.md"
            path.write_text("# missing from SQLite\n", encoding="utf-8")
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            zvec.init_db(conn)

            docs, errors = zvec.load_changed_docs(conn, [str(path)], root)
            conn.close()

        self.assertEqual(docs, [])
        self.assertEqual(errors, [f"not_in_sqlite_index {path.resolve()}"])

    def test_changed_noncurrent_fact_prunes_old_vector_and_restores_parity(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            path = root / "superseded.md"
            path.write_text("# superseded fact\n", encoding="utf-8")
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            memory_index.init_db(conn)
            zvec.init_db(conn)
            insert_memory_doc(conn, path, "a" * 64, fact_status="superseded")
            conn.execute(
                """
                INSERT INTO memory_vector_index_state(
                  path,memory_id,rel_path,doc_sha256,status,chunk_count,
                  embedding_model,embedding_dim,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    str(path), "a" * 64, "工作流/superseded.md", "b" * 64,
                    "indexed", 1, "binding", 768, "now",
                ),
            )
            conn.execute(
                """
                INSERT INTO memory_vector_chunks(
                  chunk_id,memory_id,path,rel_path,doc_sha256,chunk_sha256,
                  chunk_index,memory_type,track,embedding_model,embedding_dim,indexed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "old-chunk", "a" * 64, str(path), "工作流/superseded.md",
                    "b" * 64, "c" * 64, 0, "workflow", "workflow",
                    "binding", 768, "now",
                ),
            )
            before = zvec.parity_report(conn, root)
            store = mock.Mock()
            sqlite_module = mock.Mock(
                VAULT_ROOT=root,
                assert_schema_ready=memory_index.assert_schema_ready,
            )
            namespace = Namespace(
                scan=False,
                prune=True,
                changed_file=[str(path)],
                model="fixture-model",
                embedding_dim=768,
                device="cpu",
                cache_folder="",
                require_local_model=False,
                model_revision="fixture-revision",
                force=False,
                json=True,
                _embedding_binding={"binding_id": "binding"},
            )
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                exit_code = zvec.run_indexing(namespace, sqlite_module, conn, store)
            payload = json.loads(stream.getvalue())
            state_count = int(
                conn.execute("SELECT COUNT(*) FROM memory_vector_index_state").fetchone()[0]
            )
            chunk_count = int(
                conn.execute("SELECT COUNT(*) FROM memory_vector_chunks").fetchone()[0]
            )
            conn.close()

        self.assertFalse(before["parity_ok"], before)
        self.assertEqual(before["stale_paths"], [str(path)])
        self.assertEqual(exit_code, 0, payload)
        self.assertEqual(payload["docs_seen"], 0)
        self.assertEqual(payload["docs_skipped"], 0)
        self.assertEqual(payload["docs_error"], 0)
        self.assertEqual(payload["errors"], [])
        self.assertEqual(payload["pruned_docs"], 1)
        self.assertTrue(payload["parity"]["parity_ok"], payload["parity"])
        self.assertEqual(state_count, 0)
        self.assertEqual(chunk_count, 0)
        store.replace_chunks.assert_called_once_with([], [], ["old-chunk"])

    def test_shared_embedder_rejects_nonfinite_document_and_query_vectors(self) -> None:
        class FakeRow(list[float]):
            def tolist(self) -> list[float]:
                return list(self)

        class FakeArray:
            ndim = 2

            def __init__(self, values: list[list[float]]) -> None:
                self.values = values
                self.shape = (len(values), len(values[0]))

            def __iter__(self):
                return iter(FakeRow(value) for value in self.values)

            def __getitem__(self, key):
                if isinstance(key, tuple):
                    _rows, columns = key
                    return FakeArray([value[columns] for value in self.values])
                return self.values[key]

        fake_numpy = mock.Mock(
            asarray=mock.Mock(side_effect=lambda raw, dtype: FakeArray(raw))
        )
        embedder = zvec.EmbeddingGemmaEmbedder("fixture", 3)
        with mock.patch.dict(sys.modules, {"numpy": fake_numpy}):
            for value in (math.nan, math.inf, -math.inf):
                with self.subTest(value=value), self.assertRaisesRegex(
                    zvec.EmbedderError, "embedding_vector_nonfinite"
                ):
                    embedder._normalize_vectors([[1.0, value, 2.0]], 1)

            with mock.patch.object(
                embedder,
                "_load_model",
                return_value=mock.Mock(
                    encode_query=mock.Mock(return_value=[[1.0, math.nan, 2.0]])
                ),
            ), self.assertRaisesRegex(zvec.EmbedderError, "embedding_vector_nonfinite"):
                embedder.embed_query("fixture")

    def test_vector_schema_v3_adds_memory_id_only_through_init(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        zvec.init_db(conn)
        zvec.assert_schema_ready(conn)
        version = conn.execute(
            "SELECT value FROM meta WHERE key='memory_vector_schema_version'"
        ).fetchone()[0]
        chunk_columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(memory_vector_chunks)")
        }
        state_columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(memory_vector_index_state)")
        }
        conn.close()
        self.assertEqual(version, zvec.VECTOR_SCHEMA_VERSION)
        self.assertIn("memory_id", chunk_columns)
        self.assertIn("memory_id", state_columns)

    def test_ordinary_schema_assert_never_alters_v2_tables(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.executescript(
            """
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO meta(key,value) VALUES('memory_vector_schema_version','2');
            CREATE TABLE memory_vector_chunks(chunk_id TEXT PRIMARY KEY, path TEXT);
            CREATE TABLE memory_vector_index_state(
              path TEXT PRIMARY KEY,
              chunk_policy_version TEXT DEFAULT '3'
            );
            """
        )
        before = tuple(
            conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")
        )
        before_columns = tuple(
            conn.execute("PRAGMA table_info(memory_vector_chunks)")
        )
        with self.assertRaisesRegex(
            sqlite3.OperationalError, "STATE_SCHEMA_MIGRATION_REQUIRED"
        ):
            zvec.assert_schema_ready(conn)
        after = tuple(
            conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")
        )
        after_columns = tuple(
            conn.execute("PRAGMA table_info(memory_vector_chunks)")
        )
        conn.close()
        self.assertEqual(after, before)
        self.assertEqual(after_columns, before_columns)

    def test_ready_runtime_cannot_use_raw_init(self) -> None:
        namespace = Namespace(_runtime_status={"ready": True, "phase": "ready"})
        with self.assertRaisesRegex(RuntimeError, "ZVEC_INIT_CAPABILITY_REQUIRED"):
            zvec.assert_installer_init_capability(namespace)

    def test_collection_property_opens_existing_and_never_creates(self) -> None:
        store = zvec.ZvecStore(Path("/private/existing-zvec"), 768)
        with (
            mock.patch.object(store, "open_existing") as opened,
            mock.patch.object(store, "init") as initialized,
        ):
            self.assertIsNone(store.collection)
        opened.assert_called_once_with()
        initialized.assert_not_called()

    def test_close_drops_native_collection_reference_idempotently(self) -> None:
        store = zvec.ZvecStore(Path("/private/existing-zvec"), 768)
        store._collection = object()
        with mock.patch.object(zvec.gc, "collect") as collected:
            store.close()
            store.close()
        self.assertIsNone(store._collection)
        collected.assert_called_once_with()

    def test_ready_scan_asserts_existing_schema_without_init(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        memory_index.init_db(conn)
        zvec.init_db(conn)
        store = mock.Mock()
        sqlite_module = mock.Mock(VAULT_ROOT=Path("/vault"))
        namespace = Namespace(
            init=False,
            scan=True,
            prune=False,
            report=False,
            changed_file=[],
            search=None,
            state_db="/private/state.sqlite",
            collection_path="/private/zvec",
            embedding_dim=768,
            model="model",
            model_revision="revision",
            model_manifest="/private/model.json",
            json=True,
            lock_timeout=2.0,
        )
        stream = io.StringIO()
        with (
            mock.patch.object(zvec, "load_sqlite_index", return_value=sqlite_module),
            mock.patch.object(zvec, "connect", return_value=conn),
            mock.patch.object(zvec, "ZvecStore", return_value=store),
            mock.patch.object(zvec, "resolve_embedding_binding", return_value={}),
            mock.patch.object(zvec, "run_indexing", return_value=0) as indexed,
            mock.patch.object(zvec, "zvec_lock", return_value=contextlib.nullcontext()),
            mock.patch.object(zvec, "init_db", wraps=zvec.init_db) as initialized,
            contextlib.redirect_stdout(stream),
        ):
            self.assertEqual(zvec.run_locked(namespace), 0, stream.getvalue())
        initialized.assert_not_called()
        indexed.assert_called_once()
        store.init.assert_not_called()
        conn.close()

    def test_vector_rows_dedupe_renamed_paths_by_memory_id(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        zvec.init_db(conn)
        memory_id = "a" * 64
        rows = (
            ("old-chunk", "/vault/old.md", "工作流/old.md", 0),
            ("new-chunk", "/vault/new.md", "工作流/new.md", 0),
        )
        for chunk_id, path, rel_path, chunk_index in rows:
            conn.execute(
                """
                INSERT INTO memory_vector_chunks(
                  chunk_id,memory_id,path,rel_path,doc_sha256,chunk_sha256,
                  chunk_index,title,chunk_text,memory_type,track,embedding_model,
                  embedding_dim,indexed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    chunk_id, memory_id, path, rel_path, "b" * 64, "c" * 64,
                    chunk_index, rel_path, "body", "workflow", "workflow",
                    "binding", 768, "now",
                ),
            )
        result = zvec.vector_rows(
            conn,
            [("old-chunk", 0.30), ("new-chunk", 0.10)],
            expected_embedding_binding="binding",
        )
        conn.close()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["memory_id"], memory_id)
        self.assertEqual(result[0]["rel_path"], "工作流/new.md")

    def test_prune_stale_identity_removes_old_rename_vector(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            current_path = root / "new.md"
            current_path.write_text("# current\n", encoding="utf-8")
            doc = indexed_doc(current_path, "a" * 64)
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            zvec.init_db(conn)
            conn.execute(
                "INSERT INTO memory_vector_index_state(path,memory_id,rel_path,status,updated_at) "
                "VALUES(?,?,?,?,?)",
                (str(root / "old.md"), doc.memory_id, "工作流/old.md", "indexed", "now"),
            )
            conn.execute(
                """
                INSERT INTO memory_vector_chunks(
                  chunk_id,memory_id,path,rel_path,doc_sha256,chunk_sha256,
                  chunk_index,memory_type,track,embedding_model,embedding_dim,indexed_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "old-chunk", doc.memory_id, str(root / "old.md"),
                    "工作流/old.md", "b" * 64, "c" * 64, 0, "workflow",
                    "workflow", "binding", 768, "now",
                ),
            )
            store = mock.Mock()
            removed = zvec.prune_stale_identity(conn, store, doc)
            remaining = conn.execute(
                "SELECT COUNT(*) FROM memory_vector_chunks"
            ).fetchone()[0]
            state_remaining = conn.execute(
                "SELECT COUNT(*) FROM memory_vector_index_state"
            ).fetchone()[0]
            conn.close()
        self.assertEqual(removed, 1)
        self.assertEqual(remaining, 0)
        self.assertEqual(state_remaining, 0)
        store.replace_chunks.assert_called_once_with([], [], ["old-chunk"])

    def test_duplicate_document_identity_fails_closed(self) -> None:
        memory_id = "a" * 64
        docs = [
            indexed_doc(Path("/vault/one.md"), memory_id),
            indexed_doc(Path("/vault/two.md"), memory_id),
        ]
        with self.assertRaisesRegex(sqlite3.IntegrityError, "DUPLICATE_MEMORY_ID"):
            zvec.assert_unique_doc_memory_ids(docs)


if __name__ == "__main__":
    unittest.main()
