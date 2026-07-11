from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "scripts"


class NamespaceCleanTests(unittest.TestCase):
    def test_runtime_has_no_compatibility_entrypoints(self) -> None:
        forbidden_prefix = "codex" + "_"
        legacy_dispatcher = "legacy" + "_entrypoint.py"
        forbidden_files = [
            path.name
            for path in SCRIPT_ROOT.iterdir()
            if path.is_file()
            and (path.name.startswith(forbidden_prefix) or path.name == legacy_dispatcher)
        ]
        self.assertEqual(forbidden_files, [])

    def test_runtime_uses_only_agent_memory_environment_namespace(self) -> None:
        forbidden_namespace = "CODEX" + "_MEMORY_"
        offenders = []
        for path in sorted(SCRIPT_ROOT.glob("*.py")):
            if forbidden_namespace in path.read_text(encoding="utf-8"):
                offenders.append(path.name)
        self.assertEqual(offenders, [])

        env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertNotIn(forbidden_namespace, env_example)


if __name__ == "__main__":
    unittest.main()
