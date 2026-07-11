from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

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


if __name__ == "__main__":
    unittest.main()
