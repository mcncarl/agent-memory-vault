from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from unittest import mock

from tests.test_memoryctl import load_memoryctl


class WindowsReadOnlyContractTests(unittest.TestCase):
    def test_memoryctl_blocks_mutations_before_readiness_or_child_process(self) -> None:
        for action in ("prepare", "apply", "cancel"):
            with self.subTest(action=action):
                module = load_memoryctl()
                module._PLATFORM_NAME = "nt"
                readiness = mock.Mock(side_effect=AssertionError("readiness must not run"))
                child = mock.Mock(side_effect=AssertionError("child must not run"))
                module.assert_runtime_ready = readiness
                stdout = io.StringIO()
                with (
                    mock.patch.object(module.subprocess, "run", child),
                    mock.patch.object(
                        sys,
                        "argv",
                        ["memoryctl", "--actor", "ailu", "write", action, "--json"],
                    ),
                    contextlib.redirect_stdout(stdout),
                ):
                    returncode = module.main()

                payload = json.loads(stdout.getvalue())
                self.assertEqual(returncode, 2)
                self.assertEqual(payload["reason_code"], "WINDOWS_READ_ONLY")
                readiness.assert_not_called()
                child.assert_not_called()

    def test_writer_blocks_mutations_before_request_or_state_access(self) -> None:
        import agent_memory_write as writer

        for action in ("prepare", "apply", "cancel"):
            with self.subTest(action=action):
                readiness = mock.Mock(side_effect=AssertionError("readiness must not run"))
                request_reader = mock.Mock(side_effect=AssertionError("request must not be read"))
                stdout = io.StringIO()
                with (
                    mock.patch.object(writer, "PLATFORM_NAME", "nt"),
                    mock.patch.object(writer, "assert_runtime_ready", readiness),
                    mock.patch.object(writer, "_read_request", request_reader),
                    mock.patch.object(
                        sys,
                        "argv",
                        ["agent_memory_write.py", "--actor", "ailu", "--json", action],
                    ),
                    contextlib.redirect_stdout(stdout),
                ):
                    returncode = writer.main()

                payload = json.loads(stdout.getvalue())
                self.assertEqual(returncode, 2)
                self.assertEqual(payload["reason_code"], "WINDOWS_READ_ONLY")
                readiness.assert_not_called()
                request_reader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
