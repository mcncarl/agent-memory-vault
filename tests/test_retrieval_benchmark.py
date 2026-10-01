from __future__ import annotations

import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
import sqlite3
from argparse import Namespace
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_retrieval_benchmark as benchmark


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "scripts" / "agent_memory_retrieval_benchmark.py"


def run_benchmark(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(RUNNER), *args, "--json"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


class RetrievalBenchmarkDatasetTests(unittest.TestCase):
    def test_isolated_worker_socket_base_is_fresh_and_separate_from_live_base(self) -> None:
        import agent_memory_embedding_worker as embedding_worker

        first = benchmark.isolated_worker_socket_base()
        second = benchmark.isolated_worker_socket_base()
        production = Path(embedding_worker.DEFAULT_SOCKET_BASE).expanduser().resolve()
        self.assertNotEqual(first, production)
        self.assertNotEqual(second, production)
        self.assertNotEqual(first, second)
        self.assertEqual(first.parent, production.parent)

    def test_isolated_worker_environment_never_reuses_or_loses_production_socket(self) -> None:
        production = "/private/live-production-worker.sock"
        isolated = Path("/private/benchmark-worker.sock")
        with mock.patch.dict(
            os.environ,
            {"AGENT_MEMORY_EMBEDDING_WORKER_SOCKET": production},
            clear=False,
        ):
            with benchmark.isolated_worker_environment(isolated):
                self.assertEqual(
                    os.environ["AGENT_MEMORY_EMBEDDING_WORKER_SOCKET"],
                    str(isolated.resolve()),
                )
                self.assertNotEqual(
                    os.environ["AGENT_MEMORY_EMBEDDING_WORKER_SOCKET"],
                    production,
                )
            self.assertEqual(
                os.environ["AGENT_MEMORY_EMBEDDING_WORKER_SOCKET"],
                production,
            )

    def test_canonical_lane_is_synthetic_and_vector_lock_defaults_to_two_seconds(self) -> None:
        import agent_memory_retrieve as canonical_retrieve

        with mock.patch.object(
            canonical_retrieve,
            "retrieve",
            return_value={
                "results": [],
                "ranking_version": "hybrid-v2",
                "backend_status": {},
                "degraded": False,
                "warnings": [],
            },
        ) as retrieve, mock.patch.object(sys, "argv", ["retrieval-benchmark"]):
            benchmark.run_canonical("private query", 5)
            parsed = benchmark.parse_args()

        self.assertEqual(retrieve.call_args.kwargs["actor"], "codex")
        self.assertIs(
            retrieve.call_args.kwargs["_observation_capability"],
            canonical_retrieve._SYNTHETIC_BENCHMARK_CAPABILITY,
        )
        self.assertEqual(parsed.lock_timeout, 2.0)

    def test_sqlite_baseline_opens_existing_state_read_only(self) -> None:
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        sqlite_index = mock.Mock(
            STATE_DB=Path("/private/state.sqlite"),
            secure_sqlite_connect=mock.Mock(return_value=connection),
            assert_schema_ready=mock.Mock(),
            search=mock.Mock(return_value=[{"rel_path": "工作流/example.md"}]),
            init_db=mock.Mock(),
        )
        self.assertEqual(
            benchmark.run_sqlite(sqlite_index, "query", 5),
            ["工作流/example.md"],
        )
        kwargs = sqlite_index.secure_sqlite_connect.call_args.kwargs
        self.assertFalse(kwargs["create"])
        self.assertTrue(kwargs["read_only"])
        sqlite_index.assert_schema_ready.assert_called_once_with(connection)
        sqlite_index.init_db.assert_not_called()

    def test_required_shadow_observation_persists_fingerprints_and_regression_count(self) -> None:
        import agent_memory_search as production_search

        connection = sqlite3.connect(":memory:")
        first = "1" * 64
        second = "2" * 64
        metadata = {
            "v1_result_memory_ids": [first],
            "v2_result_memory_ids": [second],
            "worker_status": "reused",
            "worker_restart_count": 0,
            "degraded": False,
        }
        with (
            mock.patch.object(production_search, "connect", return_value=connection),
            mock.patch.object(
                production_search.memory_index,
                "assert_schema_ready",
            ) as schema_ready,
            mock.patch.object(production_search.memory_index, "init_db") as init_db,
            mock.patch.object(production_search.observability, "record_search") as recorded,
        ):
            self.assertTrue(
                benchmark.record_required_shadow_observation(
                    "private benchmark query",
                    ["工作流/example.md"],
                    metadata,
                    duration_ms=12,
                    regression_count=1,
                )
            )
        schema_ready.assert_called_once_with(connection)
        init_db.assert_not_called()
        kwargs = recorded.call_args.kwargs
        self.assertEqual(kwargs["ranking_mode"], "shadow")
        self.assertEqual(kwargs["required_case_regression_count"], 1)
        self.assertEqual(kwargs["memory_ids"], [second])
        self.assertEqual(
            kwargs["v1_result_fingerprint"],
            __import__("hashlib").sha256(first.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            kwargs["v2_result_fingerprint"],
            __import__("hashlib").sha256(second.encode("utf-8")).hexdigest(),
        )
        connection.close()

    def test_required_shadow_observation_fails_closed_on_old_index_without_migration(self) -> None:
        import agent_memory_search as production_search

        connection = sqlite3.connect(":memory:")
        with (
            mock.patch.object(production_search, "connect", return_value=connection),
            mock.patch.object(
                production_search.memory_index,
                "assert_schema_ready",
                side_effect=sqlite3.OperationalError("STATE_SCHEMA_MIGRATION_REQUIRED"),
            ),
            mock.patch.object(production_search.memory_index, "init_db") as init_db,
            mock.patch.object(production_search.observability, "record_search") as recorded,
        ):
            self.assertFalse(
                benchmark.record_required_shadow_observation(
                    "private benchmark query",
                    ["工作流/example.md"],
                    {
                        "v1_result_memory_ids": ["1" * 64],
                        "v2_result_memory_ids": ["2" * 64],
                    },
                    duration_ms=12,
                    regression_count=0,
                )
            )
        init_db.assert_not_called()
        recorded.assert_not_called()
        self.assertEqual(
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
            ).fetchone()[0],
            0,
        )
        connection.close()

    def test_public_sample_is_explicit_and_safe(self) -> None:
        metadata, cases = benchmark.load_dataset("")
        self.assertEqual(metadata["privacy"], "public_sample")
        self.assertGreaterEqual(len(cases), 5)
        self.assertTrue(all("fake" in case["tags"] for case in cases))
        self.assertTrue(all(int(case["required_at"]) > 0 for case in cases))
        mandatory = [case for case in cases if benchmark.is_mandatory_auto_archive_case(case)]
        self.assertEqual(len(mandatory), 1)
        self.assertEqual(mandatory[0]["required_at"], 5)

    def test_success_attestation_cannot_select_cases(self) -> None:
        parsed = Namespace(
            attest_success=True,
            case_id=["only-one"],
            json=True,
        )
        stream = io.StringIO()
        with mock.patch.object(benchmark, "parse_args", return_value=parsed), redirect_stdout(stream):
            self.assertEqual(benchmark.main(), 2)
        self.assertEqual(
            json.loads(stream.getvalue())["error"],
            "success_attestation_forbids_case_selection",
        )

    def test_required_set_fingerprint_and_mandatory_case_are_content_bound(self) -> None:
        cases = [{
            "id": "mandatory",
            "query": benchmark.MANDATORY_AUTO_ARCHIVE_QUERY,
            "expected": [benchmark.MANDATORY_AUTO_ARCHIVE_EXPECTED],
            "required_at": 5,
        }]
        self.assertTrue(benchmark.is_mandatory_auto_archive_case(cases[0]))
        first = benchmark.required_case_set_sha256(cases)
        changed = [{**cases[0], "expected": ["工作流/其他.md"]}]
        self.assertNotEqual(first, benchmark.required_case_set_sha256(changed))
        self.assertFalse(benchmark.is_mandatory_auto_archive_case(changed[0]))

    def test_legacy_private_array_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            path = Path(raw_tmp) / "private.json"
            path.write_text(
                json.dumps([{"id": "one", "query": "private words", "expected": ["项目/private.md"]}]),
                encoding="utf-8",
            )
            metadata, cases = benchmark.load_dataset(str(path))
        self.assertEqual(metadata["privacy"], "private_local")
        self.assertEqual(cases[0]["required_at"], 0)

    def test_unsafe_expected_path_and_duplicate_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            path = Path(raw_tmp) / "bad.json"
            path.write_text(
                json.dumps({
                    "privacy": "private_local",
                    "cases": [
                        {"id": "same", "query": "a", "expected": ["../secret.md"]},
                        {"id": "same", "query": "b", "expected": ["项目/b.md"]},
                    ],
                }),
                encoding="utf-8",
            )
            with self.assertRaises(benchmark.DatasetError):
                benchmark.load_dataset(str(path))

    def test_explicit_file_cannot_self_declare_public(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            path = Path(raw_tmp) / "claims-public.json"
            path.write_text(
                json.dumps({
                    "privacy": "public_sample",
                    "cases": [{"id": "one", "query": "private words", "expected": ["项目/private.md"]}],
                }),
                encoding="utf-8",
            )
            metadata, _ = benchmark.load_dataset(str(path))
        self.assertEqual(metadata["declared_privacy"], "public_sample")
        self.assertEqual(metadata["privacy"], "private_local")

    def test_private_stdout_redacts_query_expected_and_dataset_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            private_case_id = "PRIVATE_CASE_ID_MUST_NOT_APPEAR"
            private_query = "private query alpha bravo"
            expected_path = "项目/private-memory.md"
            path = Path(raw_tmp) / "private-fixture.json"
            path.write_text(
                json.dumps({
                    "privacy": "public_sample",
                    "name": "must-not-be-trusted",
                    "cases": [{"id": private_case_id, "query": private_query, "expected": [expected_path]}],
                }),
                encoding="utf-8",
            )
            parsed = Namespace(
                limit=5,
                json=True,
                no_vector=True,
                case_id=[],
                benchmark_file=str(path),
                show_private_details=False,
            )
            stream = io.StringIO()
            with mock.patch.object(benchmark, "parse_args", return_value=parsed), \
                 mock.patch.object(benchmark, "load_module", return_value=object()), \
                 mock.patch.object(benchmark, "run_sqlite", return_value=[expected_path]), \
                 redirect_stdout(stream):
                self.assertEqual(benchmark.main(), 0)
            stdout = stream.getvalue()
        self.assertNotIn(private_query, stdout)
        self.assertNotIn(private_case_id, stdout)
        self.assertNotIn(expected_path, stdout)
        self.assertNotIn(str(path), stdout)
        payload = json.loads(stdout)
        self.assertTrue(payload["private_details_redacted"])
        self.assertNotIn("path", payload["dataset"])
        self.assertEqual(
            set(payload["records"][0]),
            {
                "case_ref",
                "query_sha256",
                "query_length",
                "required_at",
                "sqlite_rank",
                "vector_rank",
                "hybrid_rank",
                "canonical_rank",
            },
        )
        self.assertRegex(payload["records"][0]["case_ref"], r"^case-001-[0-9a-f]{12}$")

    def test_private_human_output_redacts_vector_exception(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            private_case_id = "PRIVATE_VECTOR_CASE_ID_MUST_NOT_APPEAR"
            private_query = "private query charlie delta"
            expected_path = "项目/private-vector.md"
            path = Path(raw_tmp) / "private-vector-fixture.json"
            path.write_text(
                json.dumps([{"id": private_case_id, "query": private_query, "expected": [expected_path]}]),
                encoding="utf-8",
            )
            parsed = Namespace(
                limit=5,
                json=False,
                no_vector=False,
                case_id=[],
                benchmark_file=str(path),
                show_private_details=False,
            )
            stream = io.StringIO()
            error = RuntimeError(f"failed for {private_query} at {path}")
            with mock.patch.object(benchmark, "parse_args", return_value=parsed), \
                 mock.patch.object(benchmark, "load_module", side_effect=[object(), error]), \
                 mock.patch.object(benchmark, "run_sqlite", return_value=[expected_path]), \
                 redirect_stdout(stream):
                self.assertEqual(benchmark.main(), 2)
            stdout = stream.getvalue()
        self.assertNotIn(private_query, stdout)
        self.assertNotIn(private_case_id, stdout)
        self.assertNotIn(expected_path, stdout)
        self.assertNotIn(str(path), stdout)
        self.assertIn("vector error=[redacted:", stdout)

    def test_private_gate_failure_uses_case_ref_not_raw_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            private_case_id = "PRIVATE_GATE_CASE_ID_MUST_NOT_APPEAR"
            path = Path(raw_tmp) / "fixture.json"
            path.write_text(
                json.dumps(
                    {
                        "privacy": "private_local",
                        "cases": [
                            {
                                "id": private_case_id,
                                "query": "private gate query",
                                "expected": ["项目/private-gate.md"],
                                "required_at": 1,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            parsed = Namespace(
                limit=5,
                json=True,
                no_vector=True,
                case_id=[],
                benchmark_file=str(path),
                show_private_details=False,
            )
            stream = io.StringIO()
            with mock.patch.object(benchmark, "parse_args", return_value=parsed), \
                 mock.patch.object(benchmark, "load_module", return_value=object()), \
                 mock.patch.object(benchmark, "run_sqlite", return_value=[]), \
                 redirect_stdout(stream):
                self.assertEqual(benchmark.main(), 3)
            stdout = stream.getvalue()
        self.assertNotIn(private_case_id, stdout)
        failure = json.loads(stdout)["gate_failures"][0]
        self.assertEqual(set(failure), {"case_ref", "backend", "required_at", "rank"})
        self.assertRegex(failure["case_ref"], r"^case-001-[0-9a-f]{12}$")

    def test_public_output_keeps_diagnostic_case_details(self) -> None:
        parsed = Namespace(
            limit=5,
            json=True,
            no_vector=True,
            case_id=["sample-field-rules"],
            benchmark_file="",
            show_private_details=False,
        )
        stream = io.StringIO()
        with mock.patch.object(benchmark, "parse_args", return_value=parsed), \
             mock.patch.object(benchmark, "load_module", return_value=object()), \
             mock.patch.object(
                 benchmark,
                 "run_sqlite",
                 return_value=["工作流/Agent记忆字段规范.md"],
             ), \
             redirect_stdout(stream):
            self.assertEqual(benchmark.main(), 0)
        stdout = stream.getvalue()
        self.assertIn("sample-field-rules", stdout)
        self.assertIn("Agent记忆字段规范", stdout)
        self.assertIn("工作流/Agent记忆字段规范.md", stdout)

    def test_vector_benchmark_is_read_only_and_rechecks_runtime_binding(self) -> None:
        parsed = Namespace(
            limit=5,
            json=True,
            no_vector=False,
            case_id=["sample-field-rules"],
            benchmark_file="",
            show_private_details=False,
            lock_timeout=9.0,
        )
        connection = mock.Mock()
        store = mock.Mock()
        embedder = mock.Mock()
        binding = {
            "model": "fake-model",
            "model_revision": "a" * 40,
            "embedding_dim": 768,
            "model_manifest_sha256": "b" * 64,
            "binding_id": "c" * 64,
        }
        zvec_module = mock.Mock(
            unsafe=True,
            DEFAULT_COLLECTION_PATH=Path("/fake/zvec"),
            DEFAULT_EMBEDDING_DIM=768,
            DEFAULT_MODEL="fake-model",
            DEFAULT_MODEL_REVISION="a" * 40,
            DEFAULT_MODEL_MANIFEST=Path("/fake/model-manifest.json"),
            DEFAULT_REQUIRE_LOCAL_MODEL=True,
            DEFAULT_DEVICE="cpu",
            connect=mock.Mock(return_value=connection),
            ZvecStore=mock.Mock(return_value=store),
            EmbeddingGemmaEmbedder=mock.Mock(return_value=embedder),
            resolve_embedding_binding=mock.Mock(return_value=binding),
            assert_index_binding=mock.Mock(),
            assert_schema_ready=mock.Mock(),
            init_db=mock.Mock(),
        )
        stream = io.StringIO()
        with (
            mock.patch.object(benchmark, "parse_args", return_value=parsed),
            mock.patch.object(benchmark, "load_module", side_effect=[object(), zvec_module]),
            mock.patch.object(
                benchmark,
                "run_sqlite",
                return_value=["工作流/Agent记忆字段规范.md"],
            ),
            mock.patch.object(
                benchmark,
                "run_vector",
                return_value=["工作流/Agent记忆字段规范.md"],
            ),
            redirect_stdout(stream),
        ):
            self.assertEqual(benchmark.main(), 0)

        zvec_module.connect.assert_called_once_with(read_only=True)
        zvec_module.assert_schema_ready.assert_called_once_with(connection)
        self.assertEqual(zvec_module.resolve_embedding_binding.call_count, 2)
        self.assertEqual(
            zvec_module.assert_index_binding.call_args_list,
            [
                mock.call(connection, "c" * 64),
                mock.call(connection, "c" * 64),
            ],
        )
        zvec_module.init_db.assert_not_called()
        store.init.assert_not_called()
        store.close.assert_called_once_with()
        connection.close.assert_called_once_with()

    def test_vector_query_embeds_before_short_shared_open_and_query_lock(self) -> None:
        events: list[str] = []

        @contextmanager
        def recorded_lock(*, exclusive: bool, timeout: float):
            self.assertFalse(exclusive)
            self.assertEqual(timeout, 2.0)
            events.append("lock_enter")
            try:
                yield
            finally:
                events.append("lock_exit")

        embedder = mock.Mock()

        def embed(_query: str) -> list[float]:
            events.append("embed")
            return [0.1, 0.2]

        embedder.embed_query.side_effect = embed
        store = mock.Mock()
        store.open_existing.side_effect = lambda: events.append("open_existing")
        store.search.side_effect = lambda _embedding, _limit: (
            events.append("query") or [("chunk-1", 0.1)]
        )
        store.close.side_effect = lambda: events.append("close")
        zvec_module = mock.Mock(
            zvec_lock=recorded_lock,
            vector_rows=mock.Mock(
                side_effect=lambda *_args, **_kwargs: (
                    events.append("rows") or [{"rel_path": "工作流/example.md"}]
                )
            ),
        )
        results = benchmark.run_vector(
            zvec_module,
            mock.Mock(),
            store,
            embedder,
            "private query",
            5,
            lock_timeout=2.0,
            binding_id="d" * 64,
        )
        self.assertEqual(results, ["工作流/example.md"])
        self.assertEqual(
            events,
            [
                "embed",
                "lock_enter",
                "open_existing",
                "query",
                "close",
                "lock_exit",
                "rows",
            ],
        )
        store.init.assert_not_called()
        store.close.assert_called_once_with()
        self.assertEqual(
            zvec_module.vector_rows.call_args.kwargs["expected_embedding_binding"],
            "d" * 64,
        )

    def test_vector_search_failure_closes_collection_before_shared_lock_exit(self) -> None:
        events: list[str] = []

        @contextmanager
        def recorded_lock(*, exclusive: bool, timeout: float):
            self.assertFalse(exclusive)
            self.assertEqual(timeout, 2.0)
            events.append("lock_enter")
            try:
                yield
            finally:
                events.append("lock_exit")

        embedder = mock.Mock()
        embedder.embed_query.side_effect = lambda _query: (
            events.append("embed") or [0.1, 0.2]
        )
        store = mock.Mock()
        store.open_existing.side_effect = lambda: events.append("open_existing")

        def failed_search(_embedding: list[float], _limit: int) -> object:
            events.append("query")
            raise RuntimeError("native query failed")

        store.search.side_effect = failed_search
        store.close.side_effect = lambda: events.append("close")
        zvec_module = mock.Mock(
            zvec_lock=recorded_lock,
            vector_rows=mock.Mock(),
        )

        with self.assertRaisesRegex(RuntimeError, "native query failed"):
            benchmark.run_vector(
                zvec_module,
                mock.Mock(),
                store,
                embedder,
                "private query",
                5,
                lock_timeout=2.0,
                binding_id="d" * 64,
            )

        self.assertEqual(
            events,
            ["embed", "lock_enter", "open_existing", "query", "close", "lock_exit"],
        )
        store.close.assert_called_once_with()
        zvec_module.vector_rows.assert_not_called()

    def test_vector_setup_failure_still_closes_connection_without_store(self) -> None:
        parsed = Namespace(
            limit=5,
            json=True,
            no_vector=False,
            case_id=["sample-field-rules"],
            benchmark_file="",
            show_private_details=False,
            lock_timeout=2.0,
            production_chain=True,
            runs=1,
        )
        connection = mock.Mock()
        zvec_module = mock.Mock(
            unsafe=True,
            connect=mock.Mock(return_value=connection),
            assert_schema_ready=mock.Mock(side_effect=RuntimeError("schema unavailable")),
            ZvecStore=mock.Mock(),
        )
        stream = io.StringIO()
        with (
            mock.patch.object(benchmark, "parse_args", return_value=parsed),
            mock.patch.object(benchmark, "load_module", side_effect=[object(), zvec_module]),
            mock.patch.object(
                benchmark,
                "run_sqlite",
                return_value=["工作流/Agent记忆字段规范.md"],
            ),
            redirect_stdout(stream),
        ):
            self.assertEqual(benchmark.main(), 2)
        connection.close.assert_called_once_with()
        zvec_module.ZvecStore.assert_not_called()

    def test_production_chain_reports_hybrid_and_canonical_without_degradation(self) -> None:
        parsed = Namespace(
            limit=5,
            json=True,
            no_vector=False,
            case_id=["sample-field-rules"],
            benchmark_file="",
            show_private_details=False,
            lock_timeout=2.0,
            production_chain=True,
            runs=3,
        )

        @contextmanager
        def no_op_lock(*, exclusive: bool, timeout: float):
            del exclusive, timeout
            yield

        connection = mock.Mock()
        store = mock.Mock()
        lifecycle_events: list[str] = []
        store.close.side_effect = lambda: lifecycle_events.append("store_close")
        import weakref
        baseline_models = []

        class BaselineModel:
            def __init__(self, *_args):
                baseline_models.append(weakref.ref(self))
        binding = {
            "model": "fake-model",
            "model_revision": "a" * 40,
            "embedding_dim": 768,
            "model_manifest_sha256": "b" * 64,
            "binding_id": "c" * 64,
        }
        zvec_module = mock.Mock(
            unsafe=True,
            DEFAULT_COLLECTION_PATH=Path("/fake/zvec"),
            DEFAULT_EMBEDDING_DIM=768,
            DEFAULT_MODEL="fake-model",
            DEFAULT_MODEL_REVISION="a" * 40,
            DEFAULT_MODEL_MANIFEST=Path("/fake/model-manifest.json"),
            DEFAULT_REQUIRE_LOCAL_MODEL=True,
            DEFAULT_DEVICE="cpu",
            zvec_lock=no_op_lock,
            connect=mock.Mock(return_value=connection),
            ZvecStore=mock.Mock(return_value=store),
            EmbeddingGemmaEmbedder=BaselineModel,
            resolve_embedding_binding=mock.Mock(return_value=binding),
            assert_index_binding=mock.Mock(),
            assert_schema_ready=mock.Mock(),
            init_db=mock.Mock(),
        )
        expected = ["工作流/Agent记忆字段规范.md"]
        production_socket = "/private/live-production-worker.sock"
        isolated_socket = Path("/private/benchmark-worker.sock")
        observed_socket_namespaces: list[str] = []
        statuses = iter(("started", "reused", "reused"))

        def isolated_hybrid(
            _query: str,
            _limit: int,
            *,
            current_project: str = "",
        ) -> tuple[list[str], dict[str, object]]:
            del current_project
            self.assertTrue(baseline_models)
            self.assertTrue(all(reference() is None for reference in baseline_models))
            lifecycle_events.append("hybrid")
            observed_socket_namespaces.append(
                os.environ.get("AGENT_MEMORY_EMBEDDING_WORKER_SOCKET", "")
            )
            return expected, {
                "degraded": False,
                "all_failed": False,
                "v1_result_memory_ids": ["1" * 64],
                "v2_result_memory_ids": ["1" * 64],
                "worker_status": next(statuses),
                "worker_restart_count": 0,
            }

        stream = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {"AGENT_MEMORY_EMBEDDING_WORKER_SOCKET": production_socket},
            clear=False,
        ):
            with (
                mock.patch.object(benchmark, "parse_args", return_value=parsed),
                mock.patch.object(benchmark, "load_module", side_effect=[object(), zvec_module]),
                mock.patch.object(benchmark, "run_sqlite", return_value=expected),
                # A Mock would retain its model argument and mask collection.
                mock.patch.object(benchmark, "run_vector", new=lambda *_args, **_kwargs: expected),
                mock.patch.object(benchmark, "run_hybrid", side_effect=isolated_hybrid),
                mock.patch.object(
                    benchmark,
                    "run_canonical",
                    return_value=(expected, {"degraded": False}),
                ),
                mock.patch.object(
                    benchmark,
                    "isolated_worker_socket_base",
                    return_value=isolated_socket,
                ),
                mock.patch.object(
                    benchmark,
                    "shutdown_isolated_worker",
                    return_value=True,
                ) as shutdown,
                mock.patch.object(benchmark, "record_required_shadow_observation", return_value=True),
                redirect_stdout(stream),
            ):
                self.assertEqual(benchmark.main(), 0)
            self.assertEqual(
                os.environ["AGENT_MEMORY_EMBEDDING_WORKER_SOCKET"],
                production_socket,
            )
        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["runs"], 3)
        self.assertEqual(payload["hybrid"]["hit@5"], 1.0)
        self.assertEqual(payload["canonical_retrieve"]["mrr"], 1.0)
        self.assertFalse(payload["gate_failures"])
        self.assertEqual(
            observed_socket_namespaces,
            [str(isolated_socket.resolve())] * 3,
        )
        self.assertNotIn(production_socket, observed_socket_namespaces)
        self.assertEqual(payload["worker_lifecycle"]["cleanup_status"], "stopped")
        self.assertTrue(payload["worker_lifecycle"]["isolated"])
        store.close.assert_called_once_with()
        self.assertEqual(lifecycle_events[0], "store_close")
        self.assertEqual(lifecycle_events[1:], ["hybrid", "hybrid", "hybrid"])
        self.assertEqual(shutdown.call_args.args[1], isolated_socket)

    def test_explicit_input_errors_are_content_free_and_nonzero(self) -> None:
        with tempfile.TemporaryDirectory(prefix="PRIVATE_RETRIEVAL_DIR_") as raw_tmp:
            root = Path(raw_tmp)
            invalid_json = root / "PRIVATE_INVALID_JSON_FILENAME.json"
            invalid_json.write_text("PRIVATE_INVALID_JSON_CONTENT{", encoding="utf-8")
            invalid_fixture = root / "PRIVATE_INVALID_FIXTURE_FILENAME.json"
            invalid_fixture.write_text(
                json.dumps(
                    {
                        "privacy": "private_local",
                        "cases": [
                            {
                                "id": "PRIVATE_INVALID_FIXTURE_CASE_ID",
                                "query": "PRIVATE_INVALID_FIXTURE_QUERY",
                                "expected": ["../PRIVATE_INVALID_EXPECTED.md"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            missing = root / "PRIVATE_MISSING_FIXTURE_FILENAME.json"
            scenarios = [
                (missing, "dataset_unreadable"),
                (invalid_json, "dataset_invalid_json"),
                (invalid_fixture, "case_expected_must_be_safe_relative_markdown_path"),
            ]
            for path, expected_error in scenarios:
                with self.subTest(expected_error=expected_error):
                    completed = run_benchmark(
                        "--benchmark-file", str(path), "--no-vector"
                    )
                    self.assertEqual(completed.returncode, 2)
                    combined = completed.stdout + completed.stderr
                    self.assertEqual(json.loads(completed.stdout)["error"], expected_error)
                    self.assertNotIn(str(root), combined)
                    self.assertNotIn(path.name, combined)
                    self.assertNotIn("PRIVATE_INVALID_JSON_CONTENT", combined)
                    self.assertNotIn("PRIVATE_INVALID_FIXTURE_CASE_ID", combined)
                    self.assertNotIn("PRIVATE_INVALID_FIXTURE_QUERY", combined)
                    self.assertNotIn("PRIVATE_INVALID_EXPECTED", combined)
                    self.assertNotIn("Traceback", combined)


if __name__ == "__main__":
    unittest.main()
