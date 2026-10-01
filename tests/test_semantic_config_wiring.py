from __future__ import annotations

import argparse
import contextlib
import io
import importlib.util
import os
import sqlite3
import sys
import tempfile
import tomllib
import unittest
import uuid
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_retrieve as retrieve
import agent_memory_env as memory_env


def load_script(stem: str):
    name = f"test_semantic_wiring_{stem}_{uuid.uuid4().hex}"
    path = SCRIPTS_ROOT / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SemanticConfigWiringTests(unittest.TestCase):
    def test_public_and_windows_fresh_templates_define_every_consumed_semantic_field(self) -> None:
        semantic_keys = {
            "enabled",
            "semantic_mode",
            "ranking_version",
            "vector_dir",
            "embedding_model",
            "embedding_dim",
            "embedding_device",
            "python",
            "lock_path",
            "zvec_lock_timeout_seconds",
            "zvec_max_distance",
            "require_local_model",
            "model_revision",
            "model_manifest",
            "dependency_lock",
            "candidate_pool_min",
            "candidate_pool_factor",
            "candidate_pool_scope_min",
            "candidate_pool_max",
            "embedding_worker_socket",
            "embedding_worker_idle_seconds",
            "embedding_worker_cold_timeout_seconds",
            "embedding_worker_warm_timeout_seconds",
            "run_vector_index_after_closeout",
        }
        public = tomllib.loads(
            (REPO_ROOT / "config" / "agent-memory.example.toml").read_text(encoding="utf-8")
        )
        self.assertTrue(semantic_keys.issubset(public["semantic_retrieval"]))
        self.assertRegex(
            public["semantic_retrieval"]["model_revision"],
            r"^[0-9a-f]{40}$",
        )
        self.assertEqual(public["shadow"]["status"], "observing")
        self.assertEqual(public["shadow"]["state_dir"], "~/.config/agent-memory/shadow")

        windows = (SCRIPTS_ROOT / "install-windows.ps1").read_text(encoding="utf-8")
        windows_semantic = windows.split("[semantic_retrieval]", 1)[1].split('"@', 1)[0]
        for key in semantic_keys:
            self.assertIn(f"{key} =", windows_semantic)
        for relative in (
            r"zvec\memory_chunks_embeddinggemma_768",
            r"locks\zvec.lock",
            r"models\embeddinggemma-300m\model-manifest.json",
            "requirements-vector.lock",
            r"run\embedding.sock",
        ):
            self.assertIn(f"Join-Path $ConfigRoot '{relative}'", windows_semantic)
        windows_shadow = windows.split("[shadow]", 1)[1].split("[write_gateway]", 1)[0]
        for key in public["shadow"]:
            self.assertIn(f"{key} =", windows_shadow)
        self.assertIn("Join-Path $ConfigRoot 'shadow'", windows_shadow)

    def test_runtime_toml_drives_search_zvec_worker_and_shadow_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            config = root / "agent-memory.toml"
            shadow_root = root / "private-shadow"
            worker_socket = root / "run" / "custom.sock"
            config.write_text(
                "\n".join(
                    (
                        f'config_root = "{root}"',
                        "[semantic_retrieval]",
                        "enabled = true",
                        'semantic_mode = "required"',
                        "zvec_lock_timeout_seconds = 3.75",
                        "zvec_max_distance = 0.63",
                        "candidate_pool_min = 83",
                        "candidate_pool_factor = 11",
                        "candidate_pool_scope_min = 171",
                        "candidate_pool_max = 411",
                        f'embedding_worker_socket = "{worker_socket}"',
                        "embedding_worker_idle_seconds = 421",
                        "embedding_worker_cold_timeout_seconds = 9.5",
                        "embedding_worker_warm_timeout_seconds = 1.5",
                        f'model_revision = "{"a" * 40}"',
                        f'model_manifest = "{root / "missing-model-manifest.json"}"',
                        "run_vector_index_after_closeout = true",
                        "[shadow]",
                        f'state_dir = "{shadow_root}"',
                        "",
                    )
                ),
                encoding="utf-8",
            )
            relevant = {
                "AGENT_MEMORY_CONFIG_FILE",
                "AGENT_MEMORY_SEMANTIC_ENABLED",
                "AGENT_MEMORY_SEMANTIC_MODE",
                "AGENT_MEMORY_ZVEC_LOCK_TIMEOUT_SECONDS",
                "AGENT_MEMORY_ZVEC_MAX_DISTANCE",
                "AGENT_MEMORY_CANDIDATE_POOL_MIN",
                "AGENT_MEMORY_CANDIDATE_POOL_FACTOR",
                "AGENT_MEMORY_CANDIDATE_POOL_SCOPE_MIN",
                "AGENT_MEMORY_CANDIDATE_POOL_MAX",
                "AGENT_MEMORY_EMBEDDING_WORKER_SOCKET",
                "AGENT_MEMORY_EMBEDDING_WORKER_IDLE_SECONDS",
                "AGENT_MEMORY_EMBEDDING_WORKER_COLD_TIMEOUT_SECONDS",
                "AGENT_MEMORY_EMBEDDING_WORKER_WARM_TIMEOUT_SECONDS",
                "AGENT_MEMORY_SHADOW_STATE_DIR",
            }
            environment = {key: value for key, value in os.environ.items() if key not in relevant}
            environment["AGENT_MEMORY_CONFIG_FILE"] = str(config)
            with mock.patch.dict(os.environ, environment, clear=True):
                memory_env.reset_config_cache()
                try:
                    search = load_script("agent_memory_search")
                    zvec = load_script("agent_memory_zvec_index")
                    worker = load_script("agent_memory_embedding_worker")
                    shadow = load_script("agent_memory_shadow")
                    closeout = load_script("agent_memory_closeout")
                    with mock.patch.object(sys, "argv", ["agent_memory_closeout.py", "--actor", "test"]):
                        closeout_args = closeout.parse_args()
                finally:
                    memory_env.reset_config_cache()

        self.assertEqual(search.DEFAULT_SEMANTIC_MODE, "required")
        self.assertEqual(search.DEFAULT_ZVEC_LOCK_TIMEOUT, 3.75)
        self.assertEqual(search.DEFAULT_ZVEC_MAX_DISTANCE, 0.63)
        self.assertEqual(search.DEFAULT_CANDIDATE_POOL_MIN, 83)
        self.assertEqual(search.DEFAULT_CANDIDATE_POOL_FACTOR, 11)
        self.assertEqual(search.DEFAULT_CANDIDATE_POOL_SCOPE_MIN, 171)
        self.assertEqual(search.DEFAULT_CANDIDATE_POOL_MAX, 411)
        self.assertEqual(zvec.DEFAULT_LOCK_TIMEOUT, 3.75)
        self.assertEqual(zvec.DEFAULT_WORKER_COLD_TIMEOUT, 9.5)
        self.assertEqual(zvec.DEFAULT_WORKER_WARM_TIMEOUT, 1.5)
        self.assertEqual(zvec.DEFAULT_WORKER_IDLE_SECONDS, 421)
        self.assertEqual(zvec.DEFAULT_MODEL_REVISION, "a" * 40)
        self.assertEqual(worker.DEFAULT_MODEL_REVISION, "a" * 40)
        self.assertEqual(
            worker.DEFAULT_MODEL_MANIFEST,
            root / "missing-model-manifest.json",
        )
        self.assertEqual(worker.DEFAULT_COLD_TIMEOUT, 9.5)
        self.assertEqual(worker.DEFAULT_WARM_TIMEOUT, 1.5)
        self.assertEqual(worker.DEFAULT_IDLE_SECONDS, 421)
        self.assertEqual(worker.DEFAULT_SOCKET_BASE, worker_socket)
        self.assertEqual(shadow.SHADOW_ROOT, shadow_root)
        self.assertFalse(closeout_args.skip_zvec)

    def test_search_consumes_candidate_lock_distance_and_worker_config(self) -> None:
        environment = {
            "AGENT_MEMORY_SEMANTIC_ENABLED": "true",
            "AGENT_MEMORY_SEMANTIC_MODE": "required",
            "AGENT_MEMORY_ZVEC_LOCK_TIMEOUT_SECONDS": "3.5",
            "AGENT_MEMORY_ZVEC_MAX_DISTANCE": "0.61",
            "AGENT_MEMORY_EMBEDDING_WORKER_COLD_TIMEOUT_SECONDS": "9",
            "AGENT_MEMORY_EMBEDDING_WORKER_WARM_TIMEOUT_SECONDS": "1.25",
            "AGENT_MEMORY_EMBEDDING_WORKER_IDLE_SECONDS": "420",
            "AGENT_MEMORY_CANDIDATE_POOL_MIN": "80",
            "AGENT_MEMORY_CANDIDATE_POOL_FACTOR": "7",
            "AGENT_MEMORY_CANDIDATE_POOL_SCOPE_MIN": "160",
            "AGENT_MEMORY_CANDIDATE_POOL_MAX": "400",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            search = load_script("agent_memory_search")
            with mock.patch.object(sys, "argv", ["agent_memory_search.py", "fixture"]):
                parsed = search.parse_args()

        self.assertEqual(parsed.semantic_mode, "required")
        self.assertEqual(parsed.zvec_lock_timeout, 3.5)
        self.assertEqual(parsed.zvec_max_distance, 0.61)
        self.assertEqual(parsed.worker_cold_timeout, 9)
        self.assertEqual(parsed.worker_warm_timeout, 1.25)
        self.assertEqual(parsed.worker_idle_seconds, 420)
        base = argparse.Namespace(
            limit=10, current_project="", project_id="", agent_scope="", track="",
            memory_type="", user_id="", agent_id="", app_id="", session_id="",
            status="", has_open_loop=False, candidate_pool_min=80,
            candidate_pool_factor=7, candidate_pool_scope_min=160, candidate_pool_max=400,
        )
        self.assertEqual(search.backend_candidate_limit(base), 80)
        base.current_project = "project-a"
        self.assertEqual(search.backend_candidate_limit(base), 160)
        base.limit = 100
        self.assertEqual(search.backend_candidate_limit(base), 400)

    def test_zvec_direct_cli_consumes_lock_worker_and_candidate_config(self) -> None:
        environment = {
            "AGENT_MEMORY_ZVEC_LOCK_TIMEOUT_SECONDS": "4.5",
            "AGENT_MEMORY_EMBEDDING_WORKER_COLD_TIMEOUT_SECONDS": "8",
            "AGENT_MEMORY_EMBEDDING_WORKER_WARM_TIMEOUT_SECONDS": "1.5",
            "AGENT_MEMORY_EMBEDDING_WORKER_IDLE_SECONDS": "333",
            "AGENT_MEMORY_CANDIDATE_POOL_MIN": "72",
            "AGENT_MEMORY_CANDIDATE_POOL_FACTOR": "9",
            "AGENT_MEMORY_CANDIDATE_POOL_MAX": "360",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            zvec = load_script("agent_memory_zvec_index")
            with mock.patch.object(sys, "argv", ["agent_memory_zvec_index.py", "--report"]):
                parsed = zvec.parse_args()

        self.assertEqual(parsed.lock_timeout, 4.5)
        self.assertEqual(parsed.worker_cold_timeout, 8)
        self.assertEqual(parsed.worker_warm_timeout, 1.5)
        self.assertEqual(parsed.worker_idle_seconds, 333)
        self.assertEqual(zvec.DEFAULT_CANDIDATE_POOL_MIN, 72)
        self.assertEqual(zvec.DEFAULT_CANDIDATE_POOL_FACTOR, 9)
        self.assertEqual(zvec.DEFAULT_CANDIDATE_POOL_MAX, 360)

    def test_query_embedding_completes_before_zvec_collection_lock(self) -> None:
        zvec = load_script("agent_memory_zvec_index")
        events: list[str] = []

        class Store:
            def open_existing(self) -> None:
                events.append("open")

            def search(self, _embedding: list[float], _limit: int):
                events.append("search")
                return []

            def close(self) -> None:
                events.append("close")

        @contextlib.contextmanager
        def locked(*, exclusive: bool, timeout: float):
            self.assertTrue(exclusive)
            self.assertEqual(timeout, 2.0)
            events.append("lock_enter")
            try:
                yield
            finally:
                events.append("lock_exit")

        def embed(*_args: object, **_kwargs: object):
            events.append("embed")
            return [0.1, 0.2], {
                "worker_status": "started",
                "worker_restart_count": 0,
            }

        namespace = argparse.Namespace(
            search="private query",
            embedding_worker=True,
            model="fake",
            model_revision="a" * 40,
            model_manifest=str(Path(tempfile.gettempdir()) / "missing-model-manifest.json"),
            embedding_dim=2,
            worker_cold_timeout=12,
            worker_warm_timeout=2,
            worker_idle_seconds=600,
            device="cpu",
            cache_folder="",
            require_local_model=True,
            limit=5,
            lock_timeout=2.0,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.object(zvec, "assert_schema_ready"),
            mock.patch("agent_memory_embedding_worker.embed_query", side_effect=embed),
            mock.patch.object(zvec, "zvec_lock", side_effect=locked),
            mock.patch.object(zvec, "vector_rows", return_value=[]),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(zvec.run_search(namespace, mock.Mock(), Store()), 0)
        self.assertEqual(events, ["embed", "lock_enter", "open", "search", "close", "lock_exit"])

    def test_zvec_fails_closed_before_lock_when_model_revision_is_unbound(self) -> None:
        zvec = load_script("agent_memory_zvec_index")
        namespace = argparse.Namespace(
            search="private query",
            embedding_worker=True,
            model="fake",
            model_revision="",
            model_manifest=str(Path(tempfile.gettempdir()) / "missing-model-manifest.json"),
            embedding_dim=2,
            worker_cold_timeout=12,
            worker_warm_timeout=2,
            worker_idle_seconds=600,
            device="cpu",
            cache_folder="",
            require_local_model=True,
            limit=5,
            lock_timeout=2.0,
            json=True,
        )
        output = io.StringIO()
        with (
            mock.patch.object(zvec, "assert_schema_ready"),
            mock.patch.object(zvec, "zvec_lock") as locked,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(zvec.run_search(namespace, mock.Mock(), mock.Mock()), 2)
        payload = __import__("json").loads(output.getvalue())
        self.assertEqual(payload["reason_code"], "MODEL_REVISION_REQUIRED")
        locked.assert_not_called()

    def test_zvec_rejects_index_rows_from_another_model_binding(self) -> None:
        zvec = load_script("agent_memory_zvec_index")
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            CREATE TABLE memory_vector_index_state (
              status TEXT NOT NULL,
              embedding_model TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO memory_vector_index_state(status, embedding_model) VALUES ('indexed', 'old-binding')"
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "MODEL_BINDING_INDEX_MISMATCH",
        ):
            zvec.assert_index_binding(connection, "new-binding")
        connection.close()

    def test_canonical_retrieve_namespace_uses_search_runtime_defaults(self) -> None:
        defaults = {
            "DEFAULT_ZVEC_LOCK_TIMEOUT": 3.0,
            "DEFAULT_WORKER_COLD_TIMEOUT": 10.0,
            "DEFAULT_WORKER_WARM_TIMEOUT": 1.0,
            "DEFAULT_WORKER_IDLE_SECONDS": 480,
            "DEFAULT_ZVEC_MAX_DISTANCE": 0.6,
            "DEFAULT_CANDIDATE_POOL_MIN": 70,
            "DEFAULT_CANDIDATE_POOL_FACTOR": 12,
            "DEFAULT_CANDIDATE_POOL_SCOPE_MIN": 140,
            "DEFAULT_CANDIDATE_POOL_MAX": 420,
        }
        with mock.patch.multiple(retrieve.memory_search, **defaults):
            namespace = retrieve._search_namespace("fixture", 5, project_id="project-a")
        self.assertEqual(namespace.zvec_lock_timeout, 3.0)
        self.assertEqual(namespace.worker_cold_timeout, 10.0)
        self.assertEqual(namespace.worker_warm_timeout, 1.0)
        self.assertEqual(namespace.worker_idle_seconds, 480)
        self.assertEqual(namespace.zvec_max_distance, 0.6)
        self.assertEqual(namespace.candidate_pool_scope_min, 140)


if __name__ == "__main__":
    unittest.main()
