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
    def test_new_name_has_priority(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {
                "AGENT_MEMORY_ROOT": "/new/vault",
                "CODEX_MEMORY_ROOT": "/legacy/vault",
            },
            clear=True,
        ):
            self.assertEqual(env_value("ROOT", "/default"), "/new/vault")

    def test_legacy_name_remains_a_fallback(self) -> None:
        with mock.patch.dict(
            "os.environ", {"CODEX_MEMORY_ROOT": "/legacy/vault"}, clear=True
        ):
            self.assertEqual(env_value("ROOT", "/default"), "/legacy/vault")

    def test_default_is_used_when_both_are_absent(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(env_value("ROOT", "/default"), "/default")


if __name__ == "__main__":
    unittest.main()
