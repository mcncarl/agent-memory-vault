from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.agent_memory_env import expand_path
from scripts.agent_memory_lock import try_lock, unlock


class CrossPlatformRuntimeTests(unittest.TestCase):
    def test_home_and_space_path_expansion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="Agent Memory ") as raw_tmp:
            home = Path(raw_tmp)
            with mock.patch.dict("os.environ", {"USERPROFILE": str(home)}, clear=True):
                self.assertEqual(expand_path("$HOME/Vault With Spaces"), home / "Vault With Spaces")

    def test_process_lock_is_exclusive_and_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            lock_path = Path(raw_tmp) / "runtime.lock"
            with lock_path.open("a+", encoding="utf-8") as first, lock_path.open("a+", encoding="utf-8") as second:
                self.assertTrue(try_lock(first))
                self.assertFalse(try_lock(second))
                unlock(first)
                self.assertTrue(try_lock(second))
                unlock(second)


if __name__ == "__main__":
    unittest.main()
