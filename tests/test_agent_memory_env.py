from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from agent_memory_env import env_value


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
            self.assertEqual(env_value("ROOT", "/default"), "/default")


if __name__ == "__main__":
    unittest.main()
