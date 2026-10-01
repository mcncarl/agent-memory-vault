from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import agent_memory_embedding_worker as worker
import agent_memory_env as env
import agent_memory_search as search
import agent_memory_state as state
import agent_memory_zvec_index as zvec


class RetrievalLatencyRegressionTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX permission identity")
    def test_hardening_unchanged_permissions_does_not_mutate_db_generation(self):
        with tempfile.TemporaryDirectory() as raw_root:
            path = Path(raw_root) / "state.sqlite"
            with state.secure_sqlite_connect(path) as conn:
                conn.execute("CREATE TABLE sample(value TEXT)")
            before = env._state_check_fingerprint(path)
            with mock.patch.object(state.os, "chmod", wraps=state.os.chmod) as chmod:
                state.harden_private_file(path)
                state.harden_sqlite_files(path)
            chmod.assert_not_called()
            self.assertEqual(before, env._state_check_fingerprint(path))

    @unittest.skipUnless(os.name == "posix", "POSIX permission identity")
    def test_permission_check_does_not_invalidate_successful_integrity_scan(self):
        with tempfile.TemporaryDirectory() as raw_root:
            path = Path(raw_root) / "state.sqlite"
            with state.secure_sqlite_connect(path) as conn:
                conn.execute("CREATE TABLE sample(value TEXT)")
            env._reset_state_check_cache()
            self.addCleanup(env._reset_state_check_cache)
            with contextlib.closing(sqlite3.connect(path)) as conn:
                scans = []
                conn.set_trace_callback(scans.append)
                with mock.patch.object(env, "time", SimpleNamespace(monotonic=lambda: 10)):
                    for _ in range(2):
                        self.assertEqual(env._runtime_state_quick_check(
                            conn, path, opened_generation=env._state_check_fingerprint(path)), "ok")
                        state.harden_sqlite_files(path)
                self.assertEqual(scans.count("PRAGMA quick_check"), 1)

    @unittest.skipUnless(os.name == "posix", "POSIX permission identity")
    def test_hardening_still_repairs_each_drift_and_rejects_a_replacement_symlink(self):
        with tempfile.TemporaryDirectory() as raw_root:
            path = Path(raw_root) / "private"
            path.write_bytes(b"unchanged")
            for mode in (0o644, 0o666, 0o400):
                path.chmod(mode)
                state.harden_private_file(path)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            backup = path.with_suffix(".backup")
            path.rename(backup)
            path.symlink_to(backup)
            with self.assertRaises(state.StateSecurityError):
                state.harden_private_file(path)

    def test_vector_metadata_enrichment_is_read_only_even_when_logging_enabled(self):
        args = argparse.Namespace(no_zvec=False, no_log=False, query="workflow", limit=3,
                                  zvec_timeout=5, zvec_max_distance=0.8, as_of="")
        payload = {"results": [{"path": "/vault/workflow.md", "rel_path": "workflow.md",
                               "memory_id": "a" * 64, "raw_distance": 0.2}]}
        completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(payload), stderr="")
        with (
            mock.patch.object(search.subprocess, "run", return_value=completed),
            mock.patch.object(search, "connect", return_value=contextlib.nullcontext(object())) as connect,
            mock.patch.object(search, "enrich_from_db", side_effect=lambda result, conn: result),
            mock.patch.object(search, "annotate_temporal_from_db", side_effect=lambda result, conn, asof: result),
        ):
            rows, warnings = search.zvec_search(args)
        self.assertEqual(len(rows), 1)
        self.assertEqual(warnings, [])
        connect.assert_called_once_with(read_only=True)

    def test_native_collection_released_before_lock_exit_on_success_and_error(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                events = []
                @contextlib.contextmanager
                def lock(**kwargs):
                    events.append("lock")
                    try:
                        yield
                    finally:
                        events.append("unlock")
                store = mock.Mock()
                store.open_existing.side_effect = lambda: events.append("open")
                def query(*args):
                    events.append("query")
                    if fail:
                        raise RuntimeError("synthetic query failure")
                    return []
                store.search.side_effect = query
                store.close.side_effect = lambda: events.append("close")
                args = argparse.Namespace(search="sample", model="fake", model_revision="a"*40,
                    embedding_dim=3, embedding_worker=True, model_manifest="missing.json", limit=5,
                    worker_cold_timeout=12, worker_warm_timeout=2, worker_idle_seconds=600,
                    lock_timeout=2, json=True, _embedding_binding={"binding_id": "a"*64})
                with (
                    mock.patch.object(zvec, "assert_schema_ready"),
                    mock.patch.object(zvec, "zvec_lock", side_effect=lock),
                    mock.patch.object(zvec, "vector_rows", return_value=[]),
                    mock.patch.object(worker, "embed_query", return_value=([1, 0, 0], {})),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "synthetic"):
                            zvec.run_search(args, object(), store)
                    else:
                        self.assertEqual(zvec.run_search(args, object(), store), 0)
                self.assertEqual(events, ["lock", "open", "query", "close", "unlock"])


class WorkerDeadlineRegressionTests(unittest.TestCase):
    def test_expired_request_never_rotates_or_restarts_live_worker(self):
        with (
            tempfile.TemporaryDirectory() as raw_root,
            mock.patch.object(worker, "_request", side_effect=worker.WorkerError("WORKER_REQUEST_EXPIRED")),
            mock.patch.object(worker, "_rotate_stale_socket") as rotate,
            mock.patch.object(worker, "_start_worker") as start,
            mock.patch.object(worker, "_terminate_failed_launch") as terminate,
        ):
            with self.assertRaises(worker.WorkerError) as caught:
                worker.embed_query("sample", model="fake", revision="a" * 40,
                    embedding_dim=3, socket_base=Path(raw_root) / "worker.sock",
                    model_manifest=Path(raw_root) / "missing.json")
        self.assertEqual(caught.exception.code, "WORKER_BUSY")
        rotate.assert_not_called()
        start.assert_not_called()
        terminate.assert_not_called()

    def test_response_reads_share_one_deadline_instead_of_refreshing_timeout(self):
        now = [10.0]
        client = mock.Mock()
        pieces = iter([b'{"ok":', b'true,"protocol_version":1,', b'"identity":', b'"test"}\n'])
        def recv(size):
            now[0] += 0.04
            return next(pieces)
        client.recv.side_effect = recv
        with (
            mock.patch.object(worker.socket, "socket", return_value=client),
            mock.patch.object(worker, "time", SimpleNamespace(monotonic=lambda: now[0])),
        ):
            with self.assertRaises(worker.WorkerError) as raised:
                worker._request(Path("unused.sock"), {"identity": "test"}, 0.1)
        self.assertEqual(raised.exception.code, "WORKER_RESPONSE_TIMEOUT")
        self.assertLessEqual(client.recv.call_count, 3)
        client.close.assert_called_once_with()

    @unittest.skipUnless(hasattr(worker.socket, "AF_UNIX"), "Unix socket worker")
    def test_expired_queued_request_does_not_perform_inference(self):
        with tempfile.TemporaryDirectory() as raw_root:
            base = Path(raw_root)
            path = base / "worker.sock"
            entered = threading.Event()
            release = threading.Event()
            seen = []
            class Embedder:
                def embed_query(self, query):
                    seen.append(query)
                    if query == "first":
                        entered.set()
                        if not release.wait(timeout=5):
                            raise AssertionError("fixture was not released")
                    return [1, 0, 0]
            identity = worker.worker_identity("fake", "a"*40, 3, worker.runtime_manifest_sha256())
            thread = threading.Thread(target=worker.serve, kwargs={"path": path,
                "identity": identity, "model": "fake", "revision": "a"*40,
                "embedding_dim": 3, "idle_seconds": 10,
                "model_manifest": base / "missing.json", "embedder_factory": Embedder}, daemon=True)
            thread.start()
            def request(query, timeout=1):
                deadline = time.monotonic()+2
                while True:
                    try:
                        return worker._request(path, {"protocol_version": worker.PROTOCOL_VERSION,
                            "operation": "embed_query", "identity": identity, "query": query}, timeout)
                    except worker.WorkerError as exc:
                        if exc.code != "WORKER_CONNECT_UNAVAILABLE" or time.monotonic() >= deadline:
                            raise
                        time.sleep(0.01)
            try:
                with self.assertRaises(worker.WorkerError) as first:
                    request("first", 0.1)
                self.assertEqual(first.exception.code, "WORKER_RESPONSE_TIMEOUT")
                self.assertTrue(entered.wait(timeout=1))
                with self.assertRaises(worker.WorkerError) as expired:
                    request("expired", 0.1)
                self.assertEqual(expired.exception.code, "WORKER_RESPONSE_TIMEOUT")
                release.set()
                self.assertTrue(request("fresh")["ok"])
                self.assertEqual(seen, ["first", "fresh"])
                # The server must not hold the last private query/vector in
                # its long-lived idle frame after responding.
                deadline = time.monotonic() + 1
                while True:
                    frame = sys._current_frames().get(thread.ident)
                    while frame is not None and frame.f_code.co_name != "serve":
                        frame = frame.f_back
                    cleared = frame is not None and frame.f_locals.get("request") is None and frame.f_locals.get("vector") is None
                    del frame
                    if cleared or time.monotonic() >= deadline:
                        break
                    time.sleep(0.01)
                self.assertTrue(cleared)
            finally:
                release.set()
                worker._request(path, {"protocol_version": worker.PROTOCOL_VERSION,
                    "operation": "shutdown", "identity": identity}, 2)
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
