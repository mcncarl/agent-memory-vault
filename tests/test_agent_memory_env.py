from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_env
from agent_memory_env import env_value, reset_config_cache


class AgentMemoryEnvironmentTests(unittest.TestCase):
    def test_agent_memory_value_is_used(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"AGENT_MEMORY_ROOT": "/agent/vault"},
            clear=True,
        ):
            self.assertEqual(env_value("ROOT", "/default"), "/agent/vault")

    def test_empty_value_uses_default(self) -> None:
        with mock.patch.dict(
            "os.environ", {"AGENT_MEMORY_ROOT": ""}, clear=True
        ):
            self.assertEqual(env_value("ROOT", "/default"), "/default")

    def test_default_is_used_when_value_is_absent(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            reset_config_cache()
            self.assertEqual(env_value("ROOT", "/default"), "/default")

    def test_runtime_toml_is_used_when_environment_is_absent(self) -> None:
        with self.subTest("toml"):
            import tempfile

            with tempfile.TemporaryDirectory() as raw_root:
                config = Path(raw_root) / "agent-memory.toml"
                config.write_text(
                    'memory_root = "/configured/vault"\n'
                    '[semantic_retrieval]\npython = "/configured/vector/python"\n',
                    encoding="utf-8",
                )
                with mock.patch.dict(
                    "os.environ",
                    {"AGENT_MEMORY_CONFIG_FILE": str(config)},
                    clear=True,
                ):
                    reset_config_cache()
                    self.assertEqual(env_value("ROOT", "/default"), "/configured/vault")
                    self.assertEqual(env_value("ZVEC_PYTHON", "python3"), "/configured/vector/python")
        reset_config_cache()

    def test_repo_source_defaults_to_isolated_local_state(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            with mock.patch.object(agent_memory_env, "RUNTIME_ROOT", root), mock.patch.dict(
                "os.environ", {}, clear=True
            ):
                reset_config_cache()
                self.assertEqual(
                    env_value("STATE_DB", "$HOME/.config/agent-memory/state.sqlite"),
                    str(root / ".agent-memory" / "state.sqlite"),
                )
        reset_config_cache()

    def test_repo_dotenv_is_loaded_without_shell_export(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            (root / ".env").write_text(
                "AGENT_MEMORY_ROOT=/dotenv/vault\n"
                "AGENT_MEMORY_CONFIG_ROOT=$HOME/.config/dotenv-memory\n",
                encoding="utf-8",
            )
            with mock.patch.object(agent_memory_env, "RUNTIME_ROOT", root), mock.patch.dict(
                "os.environ", {}, clear=True
            ):
                reset_config_cache()
                self.assertEqual(env_value("ROOT", "/default"), "/dotenv/vault")
                self.assertEqual(
                    env_value("STATE_DB", "/default/state.sqlite"),
                    "$HOME/.config/dotenv-memory/state.sqlite",
                )
        reset_config_cache()


if __name__ == "__main__":
    unittest.main()
