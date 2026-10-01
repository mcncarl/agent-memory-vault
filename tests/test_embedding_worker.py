from __future__ import annotations

import contextlib
import io
import json
import signal
import stat
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_embedding_worker as worker


PINNED_REVISION = "a" * 40


class _FakeEmbedder:
    def embed_query(self, query: str) -> list[float]:
        return [float(len(query)), 0.5, -0.5]


class EmbeddingWorkerTests(unittest.TestCase):
    def test_child_only_thread_budget_is_set_before_numerical_imports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "private" / "embedding.sock"
            with (
                mock.patch.dict(worker.os.environ, {"OMP_NUM_THREADS": "32", "TOKENIZERS_PARALLELISM": "true"}),
                mock.patch.object(worker.subprocess, "Popen") as start,
            ):
                worker._start_worker(
                    socket_path, identity="a" * 64, model="fake", revision=PINNED_REVISION,
                    embedding_dim=3, idle_seconds=600, model_manifest=Path(directory) / "model.json",
                )
                environment = start.call_args.kwargs["env"]
                for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
                    self.assertEqual(environment[key], "2")
                self.assertEqual(environment["TOKENIZERS_PARALLELISM"], "false")
                self.assertEqual(worker.os.environ["OMP_NUM_THREADS"], "32")
                self.assertEqual(worker.os.environ["TOKENIZERS_PARALLELISM"], "true")
                self.assertTrue(start.call_args.kwargs["start_new_session"])

    def test_request_limit_is_64_kib_and_oversize_never_echoes_query(self) -> None:
        self.assertEqual(worker.MAX_REQUEST_BYTES, 64 * 1024)
        private_text = "private-query-must-never-appear"

        with self.assertRaises(worker.WorkerError) as client_error:
            worker._request(
                Path("/missing/embedding.sock"),
                {
                    "protocol_version": worker.PROTOCOL_VERSION,
                    "operation": "embed_query",
                    "identity": "expected",
                    "query": private_text + ("x" * worker.MAX_REQUEST_BYTES),
                },
                0.1,
            )
        self.assertEqual(client_error.exception.code, "WORKER_REQUEST_TOO_LARGE")
        self.assertNotIn(private_text, str(client_error.exception))

        with tempfile.TemporaryDirectory() as raw_root:
            socket_path = Path(raw_root) / "private" / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                3,
                worker.runtime_manifest_sha256(),
            )
            captured_output = io.StringIO()
            with (
                contextlib.redirect_stdout(captured_output),
                contextlib.redirect_stderr(captured_output),
            ):
                thread = threading.Thread(
                    target=worker.serve,
                    kwargs={
                        "path": socket_path,
                        "identity": identity,
                        "model": "fake",
                        "revision": PINNED_REVISION,
                        "embedding_dim": 3,
                        "idle_seconds": 10,
                        "embedder_factory": _FakeEmbedder,
                        "model_manifest": Path(raw_root) / "missing-manifest.json",
                    },
                    daemon=True,
                )
                thread.start()
                deadline = time.monotonic() + 2
                while not socket_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(socket_path.exists())

                oversized = (private_text.encode("utf-8") + b"x" * worker.MAX_REQUEST_BYTES)[
                    : worker.MAX_REQUEST_BYTES + 1
                ]
                self.assertEqual(len(oversized), worker.MAX_REQUEST_BYTES + 1)
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(1.0)
                try:
                    client.connect(str(socket_path))
                    client.sendall(oversized)
                    response_bytes = b""
                    while b"\n" not in response_bytes:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        response_bytes += chunk
                finally:
                    client.close()

                response = json.loads(response_bytes.split(b"\n", 1)[0])
                self.assertFalse(response["ok"])
                self.assertEqual(response["error"], "WORKER_REQUEST_TOO_LARGE")
                self.assertNotIn(private_text, response_bytes.decode("utf-8"))

                shutdown = worker._request(
                    socket_path,
                    {
                        "protocol_version": worker.PROTOCOL_VERSION,
                        "operation": "shutdown",
                        "identity": identity,
                    },
                    1.0,
                )
                self.assertTrue(shutdown["shutdown"])
                thread.join(timeout=2)

            self.assertFalse(thread.is_alive())
            self.assertNotIn(private_text, captured_output.getvalue())

    def test_identity_binds_manifest_model_revision_and_dimension(self) -> None:
        first = worker.worker_identity("model", "rev-a", 768, "a" * 64)
        self.assertEqual(first, worker.worker_identity("model", "rev-a", 768, "a" * 64))
        self.assertNotEqual(first, worker.worker_identity("model", "rev-b", 768, "a" * 64))
        self.assertNotEqual(first, worker.worker_identity("model", "rev-a", 384, "a" * 64))

    def test_owner_only_socket_serves_without_retaining_query_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_path = Path(raw_root) / "private" / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                3,
                worker.runtime_manifest_sha256(),
            )
            thread = threading.Thread(
                target=worker.serve,
                kwargs={
                    "path": socket_path,
                    "identity": identity,
                    "model": "fake",
                    "revision": PINNED_REVISION,
                    "embedding_dim": 3,
                    "idle_seconds": 1,
                    "embedder_factory": _FakeEmbedder,
                    "model_manifest": Path(raw_root) / "missing-manifest.json",
                },
                daemon=True,
            )
            thread.start()
            deadline = time.monotonic() + 2
            while not socket_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(socket_path.exists())
            self.assertEqual(stat.S_IMODE(socket_path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(socket_path.stat().st_mode), 0o600)
            response = worker._request(
                socket_path,
                {
                    "protocol_version": worker.PROTOCOL_VERSION,
                    "operation": "embed_query",
                    "identity": identity,
                    "query": "private text never logged",
                },
                1.0,
            )
            self.assertEqual(len(response["vector"]), 3)
            self.assertEqual(response["identity"], identity)
            self.assertEqual(response["protocol_version"], worker.PROTOCOL_VERSION)
            self.assertNotIn("query", response)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(socket_path.exists())
            self.assertEqual(len(list(socket_path.parent.glob("embedding.sock.stale-*"))), 1)

    def test_warm_reuse_reports_zero_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root, mock.patch.object(
            worker,
            "_request",
            return_value={"ok": True, "vector": [0.1, 0.2]},
        ), mock.patch.object(worker, "_start_worker") as start:
            vector, status = worker.embed_query(
                "query",
                model="fake",
                revision=PINNED_REVISION,
                embedding_dim=2,
                socket_base=Path(raw_root) / "private" / "embedding.sock",
                model_manifest=Path(raw_root) / "missing-manifest.json",
            )
        self.assertEqual(vector, [0.1, 0.2])
        self.assertEqual(status["worker_status"], "reused")
        self.assertEqual(status["worker_restart_count"], 0)
        self.assertEqual(status["model_revision"], PINNED_REVISION)
        self.assertEqual(status["embedding_dim"], 2)
        self.assertRegex(status["runtime_manifest_sha256"], r"^[0-9a-f]{64}$")
        start.assert_not_called()

    def test_client_rejects_every_nonfinite_vector_value(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            for bad_value in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(value=repr(bad_value)), mock.patch.object(
                    worker,
                    "_request",
                    return_value={"ok": True, "vector": [0.1, bad_value]},
                ):
                    with self.assertRaises(worker.WorkerError) as caught:
                        worker.embed_query(
                            "query",
                            model="fake",
                            revision=PINNED_REVISION,
                            embedding_dim=2,
                            socket_base=Path(raw_root) / "embedding.sock",
                            model_manifest=Path(raw_root) / "missing-manifest.json",
                        )
                self.assertEqual(caught.exception.code, "WORKER_VECTOR_NONFINITE")

    def test_server_rejects_nonfinite_model_vectors_before_serialization(self) -> None:
        class NonfiniteEmbedder:
            def __init__(self) -> None:
                self.values = iter((float("nan"), float("inf"), float("-inf")))

            def embed_query(self, _query: str) -> list[float]:
                return [0.1, next(self.values)]

        with tempfile.TemporaryDirectory() as raw_root:
            socket_path = Path(raw_root) / "private" / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                2,
                worker.runtime_manifest_sha256(),
            )
            thread = threading.Thread(
                target=worker.serve,
                kwargs={
                    "path": socket_path,
                    "identity": identity,
                    "model": "fake",
                    "revision": PINNED_REVISION,
                    "embedding_dim": 2,
                    "idle_seconds": 10,
                    "embedder_factory": NonfiniteEmbedder,
                    "model_manifest": Path(raw_root) / "missing-manifest.json",
                },
                daemon=True,
            )
            thread.start()
            deadline = time.monotonic() + 2
            while not socket_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            request = {
                "protocol_version": worker.PROTOCOL_VERSION,
                "operation": "embed_query",
                "identity": identity,
                "query": "private",
            }
            for _ in range(3):
                with self.assertRaises(worker.WorkerError) as caught:
                    worker._request(socket_path, request, 1.0)
                self.assertEqual(caught.exception.code, "WORKER_VECTOR_NONFINITE")
            response = worker._request(
                socket_path,
                {
                    "protocol_version": worker.PROTOCOL_VERSION,
                    "operation": "shutdown",
                    "identity": identity,
                },
                1.0,
            )
            self.assertTrue(response["shutdown"])
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_graceful_shutdown_targets_only_the_exact_socket_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_base = Path(raw_root) / "private" / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                3,
                worker.runtime_manifest_sha256(),
            )
            socket_path = worker.socket_path_for(identity, socket_base)
            thread = threading.Thread(
                target=worker.serve,
                kwargs={
                    "path": socket_path,
                    "identity": identity,
                    "model": "fake",
                    "revision": PINNED_REVISION,
                    "embedding_dim": 3,
                    "idle_seconds": 10,
                    "embedder_factory": _FakeEmbedder,
                    "model_manifest": Path(raw_root) / "missing-manifest.json",
                },
                daemon=True,
            )
            thread.start()
            deadline = time.monotonic() + 2
            while not socket_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(
                worker.shutdown_worker(
                    model="fake",
                    revision=PINNED_REVISION,
                    embedding_dim=3,
                    socket_base=socket_base,
                    model_manifest=Path(raw_root) / "missing-manifest.json",
                    timeout=1.0,
                )
            )
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(socket_path.exists())

    def test_request_distinguishes_connect_failure_from_connected_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            missing = Path(raw_root) / "missing.sock"
            with self.assertRaises(worker.WorkerError) as caught:
                worker._request(
                    missing,
                    {
                        "protocol_version": worker.PROTOCOL_VERSION,
                        "operation": "embed_query",
                        "identity": "expected",
                        "query": "private",
                    },
                    0.1,
                )
            self.assertEqual(caught.exception.code, "WORKER_CONNECT_UNAVAILABLE")

            socket_path = Path(raw_root) / "busy.sock"
            ready = threading.Event()

            def serve_busy() -> None:
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    server.bind(str(socket_path))
                    server.listen(1)
                    ready.set()
                    connection, _ = server.accept()
                    with connection:
                        connection.recv(4096)
                        time.sleep(0.25)
                finally:
                    server.close()

            thread = threading.Thread(target=serve_busy, daemon=True)
            thread.start()
            self.assertTrue(ready.wait(timeout=1))
            with self.assertRaises(worker.WorkerError) as caught:
                worker._request(
                    socket_path,
                    {
                        "protocol_version": worker.PROTOCOL_VERSION,
                        "operation": "embed_query",
                        "identity": "expected",
                        "query": "private",
                    },
                    0.05,
                )
            self.assertEqual(caught.exception.code, "WORKER_RESPONSE_TIMEOUT")
            thread.join(timeout=1)

    def test_connect_timeout_is_busy_and_cannot_trigger_socket_rotation(self) -> None:
        fake_client = mock.Mock()
        fake_client.connect.side_effect = socket.timeout()
        with mock.patch.object(worker.socket, "socket", return_value=fake_client):
            with self.assertRaises(worker.WorkerError) as caught:
                worker._request(
                    Path("/private/worker.sock"),
                    {
                        "protocol_version": worker.PROTOCOL_VERSION,
                        "operation": "embed_query",
                        "identity": "expected",
                        "query": "private",
                    },
                    0.05,
                )
        self.assertEqual(caught.exception.code, "WORKER_CONNECT_BUSY")
        fake_client.close.assert_called_once()

        with tempfile.TemporaryDirectory() as raw_root:
            with (
                mock.patch.object(
                    worker,
                    "_request",
                    side_effect=worker.WorkerError("WORKER_CONNECT_BUSY"),
                ),
                mock.patch.object(worker, "_rotate_stale_socket") as rotate,
                mock.patch.object(worker, "_start_worker") as start,
            ):
                with self.assertRaises(worker.WorkerError) as busy:
                    worker.embed_query(
                        "query",
                        model="fake",
                        revision=PINNED_REVISION,
                        embedding_dim=2,
                        socket_base=Path(raw_root) / "embedding.sock",
                        model_manifest=Path(raw_root) / "missing-manifest.json",
                    )
        self.assertEqual(busy.exception.code, "WORKER_BUSY")
        rotate.assert_not_called()
        start.assert_not_called()

    def test_busy_connected_worker_is_not_rotated_or_duplicated(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_base = Path(raw_root) / "embedding.sock"
            with (
                mock.patch.object(
                    worker,
                    "_request",
                    side_effect=worker.WorkerError("WORKER_RESPONSE_TIMEOUT"),
                ),
                mock.patch.object(worker, "_rotate_stale_socket") as rotate,
                mock.patch.object(worker, "_start_worker") as start,
            ):
                with self.assertRaises(worker.WorkerError) as caught:
                    worker.embed_query(
                        "query",
                        model="fake",
                        revision=PINNED_REVISION,
                        embedding_dim=2,
                        socket_base=socket_base,
                        model_manifest=Path(raw_root) / "missing-manifest.json",
                    )
            self.assertEqual(caught.exception.code, "WORKER_BUSY")
            rotate.assert_not_called()
            start.assert_not_called()

    def test_timed_out_client_does_not_crash_worker_during_late_response(self) -> None:
        first_entered = threading.Event()
        release_first = threading.Event()

        class SlowFirstEmbedder:
            def __init__(self) -> None:
                self.calls = 0

            def embed_query(self, query: str) -> list[float]:
                self.calls += 1
                if self.calls == 1:
                    first_entered.set()
                    if not release_first.wait(timeout=10):
                        raise AssertionError("test client did not release late response")
                return [float(len(query)), 0.5, -0.5]

        embedder = SlowFirstEmbedder()
        with tempfile.TemporaryDirectory() as raw_root:
            socket_path = Path(raw_root) / "private" / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                3,
                worker.runtime_manifest_sha256(),
            )
            thread = threading.Thread(
                target=worker.serve,
                kwargs={
                    "path": socket_path,
                    "identity": identity,
                    "model": "fake",
                    "revision": PINNED_REVISION,
                    "embedding_dim": 3,
                    "idle_seconds": 10,
                    "embedder_factory": lambda: embedder,
                    "model_manifest": Path(raw_root) / "missing-manifest.json",
                },
                daemon=True,
            )
            thread.start()
            deadline = time.monotonic() + 2
            while not socket_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            request = {
                "protocol_version": worker.PROTOCOL_VERSION,
                "operation": "embed_query",
                "identity": identity,
                "query": "first",
            }
            # Socket creation precedes listen(). Under load, a path-only wait
            # can observe that gap. Retry only fixture startup, not inference.
            try:
                while True:
                    try:
                        worker._request(socket_path, request, 0.05)
                    except worker.WorkerError as exc:
                        if exc.code == "WORKER_CONNECT_UNAVAILABLE" and time.monotonic() < deadline:
                            time.sleep(0.01)
                            continue
                        self.assertEqual(exc.code, "WORKER_RESPONSE_TIMEOUT")
                        break
                    self.fail("blocked inference unexpectedly returned before client timeout")
                self.assertTrue(first_entered.wait(timeout=2))
            finally:
                release_first.set()
            response = worker._request(
                socket_path,
                {**request, "query": "second"},
                2.0,
            )
            self.assertEqual(response["vector"], [6.0, 0.5, -0.5])
            worker._request(socket_path, {**request, "operation": "shutdown"}, 2.0)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_stale_socket_rotation_never_overwrites_an_existing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_path = Path(raw_root) / "embedding.sock"
            socket_path.write_text("new evidence", encoding="utf-8")
            collision = socket_path.with_name(
                f"{socket_path.name}.stale-123-456-collision"
            )
            collision.write_text("old evidence", encoding="utf-8")
            with (
                mock.patch.object(worker.time, "time_ns", return_value=123),
                mock.patch.object(worker.os, "getpid", return_value=456),
                mock.patch.object(
                    worker.uuid,
                    "uuid4",
                    side_effect=[
                        SimpleNamespace(hex="collision"),
                        SimpleNamespace(hex="unique"),
                    ],
                ),
            ):
                worker._rotate_stale_socket(socket_path)
            unique = socket_path.with_name(
                f"{socket_path.name}.stale-123-456-unique"
            )
            self.assertEqual(collision.read_text(encoding="utf-8"), "old evidence")
            self.assertEqual(unique.read_text(encoding="utf-8"), "new evidence")

    def test_model_binding_requires_pinned_revision_or_real_manifest_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            missing = root / "missing.json"
            with self.assertRaises(worker.WorkerError) as absent:
                worker.resolve_model_binding("fake", "", 3, missing)
            self.assertEqual(absent.exception.code, "MODEL_REVISION_REQUIRED")
            with self.assertRaises(worker.WorkerError) as mutable:
                worker.resolve_model_binding("fake", "main", 3, missing)
            self.assertEqual(mutable.exception.code, "MODEL_REVISION_NOT_PINNED")

            manifest = root / "model-manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "revision": "local-snapshot-v1",
                        "embedding_dim": 3,
                        "files": {
                            "model.safetensors": {"sha256": "b" * 64, "size": 1}
                        },
                    }
                ),
                encoding="utf-8",
            )
            revision, manifest_sha = worker.resolve_model_binding(
                "fake", "", 3, manifest
            )
            self.assertEqual(revision, "local-snapshot-v1")
            self.assertRegex(manifest_sha, r"^[0-9a-f]{64}$")
            first = worker.worker_identity(
                "fake", revision, 3, "c" * 64, manifest_sha
            )
            second = worker.worker_identity(
                "fake", revision, 3, "c" * 64, "d" * 64
            )
            self.assertNotEqual(first, second)

    def test_first_started_worker_request_receives_remaining_cold_budget(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_base = Path(raw_root) / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                2,
                worker.runtime_manifest_sha256(),
            )
            timeouts: list[float] = []

            def request(_path: Path, _request: dict[str, object], timeout: float):
                timeouts.append(timeout)
                if len(timeouts) < 3:
                    raise worker.WorkerError("WORKER_CONNECT_UNAVAILABLE")
                return {
                    "ok": True,
                    "protocol_version": worker.PROTOCOL_VERSION,
                    "identity": identity,
                    "vector": [0.1, 0.2],
                }

            process = mock.Mock()
            process.poll.return_value = None
            with (
                mock.patch.object(worker, "_request", side_effect=request),
                mock.patch.object(worker, "_start_worker", return_value=process),
            ):
                _vector, status = worker.embed_query(
                    "query",
                    model="fake",
                    revision=PINNED_REVISION,
                    embedding_dim=2,
                    cold_timeout=9,
                    warm_timeout=1,
                    socket_base=socket_base,
                    model_manifest=Path(raw_root) / "missing-manifest.json",
                )
            self.assertEqual(status["worker_status"], "started")
            self.assertGreater(timeouts[2], 5)

    def test_started_worker_nonfinite_response_fails_without_retry_loop(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            process = mock.Mock(pid=12345)
            process.poll.return_value = None
            with (
                mock.patch.object(
                    worker,
                    "_request",
                    side_effect=[
                        worker.WorkerError("WORKER_CONNECT_UNAVAILABLE"),
                        worker.WorkerError("WORKER_CONNECT_UNAVAILABLE"),
                        worker.WorkerError("WORKER_VECTOR_NONFINITE"),
                    ],
                ) as request,
                mock.patch.object(worker, "_start_worker", return_value=process),
                mock.patch.object(
                    worker,
                    "_terminate_failed_launch",
                    return_value=True,
                ) as terminated,
            ):
                with self.assertRaises(worker.WorkerError) as caught:
                    worker.embed_query(
                        "query",
                        model="fake",
                        revision=PINNED_REVISION,
                        embedding_dim=2,
                        cold_timeout=12,
                        warm_timeout=2,
                        socket_base=Path(raw_root) / "embedding.sock",
                        model_manifest=Path(raw_root) / "missing-manifest.json",
                    )
            self.assertEqual(caught.exception.code, "WORKER_VECTOR_NONFINITE")
            self.assertEqual(request.call_count, 3)
            terminated.assert_called_once()

    def test_stale_socket_is_restarted_once_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_base = Path(raw_root) / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                2,
                worker.runtime_manifest_sha256(),
            )
            selected = worker.socket_path_for(identity, socket_base)
            selected.write_text("stale", encoding="utf-8")
            process = mock.Mock()
            process.poll.return_value = None
            with (
                mock.patch.object(
                    worker,
                    "_request",
                    side_effect=[
                        worker.WorkerError("WORKER_UNAVAILABLE"),
                        worker.WorkerError("WORKER_UNAVAILABLE"),
                        {"ok": True, "vector": [0.1, 0.2]},
                    ],
                ),
                mock.patch.object(worker, "_start_worker", return_value=process) as started,
            ):
                _vector, status = worker.embed_query(
                    "query",
                    model="fake",
                    revision=PINNED_REVISION,
                    embedding_dim=2,
                    socket_base=socket_base,
                    model_manifest=Path(raw_root) / "missing-manifest.json",
                )
            self.assertEqual(status["worker_status"], "restarted")
            self.assertEqual(status["worker_restart_count"], 1)
            started.assert_called_once()

    def test_first_cold_start_creates_private_socket_parent_before_launch_lock(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_base = Path(raw_root) / "missing" / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                2,
                worker.runtime_manifest_sha256(),
            )
            process = mock.Mock()
            process.poll.return_value = None
            with (
                mock.patch.object(
                    worker,
                    "_request",
                    side_effect=[
                        worker.WorkerError("WORKER_UNAVAILABLE"),
                        worker.WorkerError("WORKER_UNAVAILABLE"),
                        {
                            "ok": True,
                            "protocol_version": worker.PROTOCOL_VERSION,
                            "identity": identity,
                            "vector": [0.1, 0.2],
                        },
                    ],
                ),
                mock.patch.object(worker, "_start_worker", return_value=process),
            ):
                _vector, status = worker.embed_query(
                    "query",
                    model="fake",
                    revision=PINNED_REVISION,
                    embedding_dim=2,
                    socket_base=socket_base,
                    model_manifest=Path(raw_root) / "missing-manifest.json",
                )
            self.assertEqual(status["worker_status"], "started")
            self.assertEqual(status["worker_restart_count"], 0)
            self.assertEqual(stat.S_IMODE(socket_base.parent.stat().st_mode), 0o700)

    def test_server_rejects_identity_not_bound_to_current_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            with self.assertRaisesRegex(worker.WorkerError, "WORKER_IDENTITY_MISMATCH"):
                worker.serve(
                    Path(raw_root) / "embedding.sock",
                    identity="f" * 64,
                    model="fake",
                    revision=PINNED_REVISION,
                    embedding_dim=3,
                    idle_seconds=1,
                    embedder_factory=_FakeEmbedder,
                    model_manifest=Path(raw_root) / "missing-manifest.json",
                )

    def test_client_rejects_response_from_wrong_worker_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_path = Path(raw_root) / "wrong-worker.sock"
            ready = threading.Event()

            def serve_wrong_identity() -> None:
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    server.bind(str(socket_path))
                    server.listen(1)
                    ready.set()
                    connection, _ = server.accept()
                    with connection:
                        connection.recv(4096)
                        connection.sendall(
                            b'{"ok":true,"protocol_version":1,"identity":"wrong","vector":[0.1]}\n'
                        )
                finally:
                    server.close()

            thread = threading.Thread(target=serve_wrong_identity, daemon=True)
            thread.start()
            self.assertTrue(ready.wait(timeout=1))
            with self.assertRaisesRegex(worker.WorkerError, "WORKER_RESPONSE_IDENTITY_MISMATCH"):
                worker._request(
                    socket_path,
                    {
                        "protocol_version": worker.PROTOCOL_VERSION,
                        "operation": "embed_query",
                        "identity": "expected",
                        "query": "private",
                    },
                    1.0,
                )
            thread.join(timeout=1)

    def test_stale_worker_recovery_has_one_absolute_three_second_budget(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_base = Path(raw_root) / "embedding.sock"
            identity = worker.worker_identity(
                "fake",
                PINNED_REVISION,
                2,
                worker.runtime_manifest_sha256(),
            )
            selected = worker.socket_path_for(identity, socket_base)
            selected.write_text("stale", encoding="utf-8")
            process = mock.Mock()
            process.poll.return_value = None
            started_at = time.monotonic()
            with (
                mock.patch.object(
                    worker,
                    "_request",
                    side_effect=worker.WorkerError("WORKER_UNAVAILABLE"),
                ),
                mock.patch.object(worker, "_start_worker", return_value=process) as started,
            ):
                with self.assertRaises(worker.WorkerError) as caught:
                    worker.embed_query(
                        "query",
                        model="fake",
                        revision=PINNED_REVISION,
                        embedding_dim=2,
                        cold_timeout=12,
                        warm_timeout=2,
                        socket_base=socket_base,
                        model_manifest=Path(raw_root) / "missing-manifest.json",
                    )
            elapsed = time.monotonic() - started_at
            self.assertLess(elapsed, 3.5)
            self.assertEqual(caught.exception.restart_count, 1)
            started.assert_called_once()

    def test_failed_cold_start_terminates_only_the_new_worker(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_base = Path(raw_root) / "embedding.sock"
            process = mock.Mock(pid=12345)
            process.poll.return_value = None
            with (
                mock.patch.object(
                    worker,
                    "_request",
                    side_effect=worker.WorkerError("WORKER_CONNECT_UNAVAILABLE"),
                ),
                mock.patch.object(worker, "_start_worker", return_value=process),
                mock.patch.object(
                    worker,
                    "_terminate_failed_launch",
                    return_value=True,
                ) as terminated,
            ):
                with self.assertRaises(worker.WorkerError):
                    worker.embed_query(
                        "query",
                        model="fake",
                        revision=PINNED_REVISION,
                        embedding_dim=2,
                        cold_timeout=0.12,
                        warm_timeout=0.05,
                        socket_base=socket_base,
                        model_manifest=Path(raw_root) / "missing-manifest.json",
                    )
            terminated.assert_called_once()
            self.assertIs(terminated.call_args.args[0], process)

    def test_repeated_failed_launches_leave_zero_owned_workers_and_never_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_base = Path(raw_root) / "embedding.sock"
            live: set[int] = set()
            peak = 0
            processes: list[mock.Mock] = []

            def start(*_args: object, **_kwargs: object) -> mock.Mock:
                nonlocal peak
                process = mock.Mock(pid=20000 + len(processes))
                process.poll.return_value = None
                processes.append(process)
                live.add(int(process.pid))
                peak = max(peak, len(live))
                return process

            def terminate(process: mock.Mock, _path: Path) -> bool:
                live.discard(int(process.pid))
                return True

            with (
                mock.patch.object(
                    worker,
                    "_request",
                    side_effect=worker.WorkerError("WORKER_CONNECT_UNAVAILABLE"),
                ),
                mock.patch.object(worker, "_start_worker", side_effect=start),
                mock.patch.object(
                    worker,
                    "_terminate_failed_launch",
                    side_effect=terminate,
                ),
            ):
                for _attempt in range(3):
                    with self.assertRaises(worker.WorkerError):
                        worker.embed_query(
                            "query",
                            model="fake",
                            revision=PINNED_REVISION,
                            embedding_dim=2,
                            cold_timeout=0.12,
                            warm_timeout=0.05,
                            socket_base=socket_base,
                            model_manifest=Path(raw_root) / "missing-manifest.json",
                        )
            self.assertEqual(len(processes), 3)
            self.assertEqual(peak, 1)
            self.assertFalse(live)

    def test_failed_launch_cleanup_terminates_kills_and_reaps_owned_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_path = Path(raw_root) / "embedding.sock"
            socket_path.write_text("failed worker socket", encoding="utf-8")
            process = mock.Mock(pid=34567)
            process.poll.side_effect = [None, None, -signal.SIGKILL]
            process.wait.side_effect = [
                subprocess.TimeoutExpired("worker", 0.05),
                -signal.SIGKILL,
            ]
            signals: list[int] = []
            killed = False

            def killpg(_pgid: int, sent: int) -> None:
                nonlocal killed
                signals.append(sent)
                if sent == signal.SIGKILL:
                    killed = True
                elif sent == 0 and killed:
                    raise ProcessLookupError

            with (
                mock.patch.object(worker.os, "getpgid", return_value=process.pid),
                mock.patch.object(worker.os, "killpg", side_effect=killpg),
            ):
                self.assertTrue(
                    worker._terminate_failed_launch(
                        process,
                        socket_path,
                        grace_seconds=0.05,
                    )
                )
            self.assertIn(signal.SIGTERM, signals)
            self.assertIn(0, signals)
            self.assertIn(signal.SIGKILL, signals)
            self.assertEqual(process.wait.call_count, 2)
            self.assertFalse(socket_path.exists())
            self.assertEqual(
                len(list(socket_path.parent.glob("embedding.sock.stale-*"))),
                1,
            )

    def test_failed_launch_cleans_descendants_after_session_leader_already_exited(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            socket_path = Path(raw_root) / "embedding.sock"
            socket_path.write_text("failed worker socket", encoding="utf-8")
            process = mock.Mock(pid=45678)
            process.poll.return_value = 0
            process.wait.return_value = 0
            signals: list[int] = []
            group_killed = False

            def killpg(_pgid: int, sent: int) -> None:
                nonlocal group_killed
                signals.append(sent)
                if sent == signal.SIGKILL:
                    group_killed = True
                elif sent == 0 and group_killed:
                    raise ProcessLookupError

            with mock.patch.object(worker.os, "killpg", side_effect=killpg):
                self.assertTrue(
                    worker._terminate_failed_launch(
                        process,
                        socket_path,
                        grace_seconds=0.05,
                    )
                )

            self.assertIn(signal.SIGTERM, signals)
            self.assertIn(signal.SIGKILL, signals)
            process.terminate.assert_not_called()
            process.kill.assert_not_called()
            self.assertFalse(socket_path.exists())

    def test_busy_reused_worker_never_enters_owned_process_cleanup(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_root,
            mock.patch.object(
                worker,
                "_request",
                side_effect=worker.WorkerError("WORKER_RESPONSE_TIMEOUT"),
            ),
            mock.patch.object(worker, "_terminate_failed_launch") as terminated,
        ):
            with self.assertRaises(worker.WorkerError) as caught:
                worker.embed_query(
                    "query",
                    model="fake",
                    revision=PINNED_REVISION,
                    embedding_dim=2,
                    socket_base=Path(raw_root) / "embedding.sock",
                    model_manifest=Path(raw_root) / "missing-manifest.json",
                )
            self.assertEqual(caught.exception.code, "WORKER_BUSY")
            terminated.assert_not_called()


if __name__ == "__main__":
    unittest.main()
