from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def load_bootstrap():
    path = ROOT / "scripts" / "bootstrap.py"
    spec = importlib.util.spec_from_file_location("test_bootstrap_module", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_exported_values(env_path: Path, names: list[str]) -> dict[str, str | None]:
    python_code = (
        "import json, os; "
        f"print(json.dumps({{name: os.getenv(name) for name in {names!r}}}))"
    )
    completed = subprocess.run(
        [
            "/bin/sh",
            "-c",
            '. "$1"; exec "$2" -c "$3"',
            "sh",
            str(env_path),
            sys.executable,
            python_code,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


class BootstrapEnvironmentTests(unittest.TestCase):
    def test_example_exports_configuration_to_child_processes(self) -> None:
        values = read_exported_values(
            ROOT / ".env.example",
            [
                "AGENT_MEMORY_ROOT",
                "AGENT_MEMORY_STATE_DB",
                "MEMORY_ACTOR",
                "AGENT_MEMORY_INVARIANTS",
                "AGENT_MEMORY_REQUIRE_LOCAL_MODEL",
                "AGENT_MEMORY_MODEL_REVISION",
                "AGENT_MEMORY_DEPENDENCY_LOCK",
            ],
        )
        self.assertEqual(values["AGENT_MEMORY_ROOT"], "/path/to/your/agent-memory-vault")
        self.assertTrue(values["AGENT_MEMORY_STATE_DB"].endswith("/.config/agent-memory/state.sqlite"))
        self.assertEqual(values["MEMORY_ACTOR"], "codex")
        self.assertTrue(values["AGENT_MEMORY_INVARIANTS"].endswith("/config/system-invariants.json"))
        self.assertEqual(values["AGENT_MEMORY_REQUIRE_LOCAL_MODEL"], "false")
        self.assertEqual(values["AGENT_MEMORY_MODEL_REVISION"], "")
        self.assertTrue(values["AGENT_MEMORY_DEPENDENCY_LOCK"].endswith("/requirements-vector.lock"))

    def test_generated_env_is_exported_and_shell_safe(self) -> None:
        bootstrap = load_bootstrap()
        with tempfile.TemporaryDirectory(prefix="agent memory bootstrap ") as temp:
            root = Path(temp)
            memory_root = root / "memory vault"
            config_root = root / "config root"
            state_db = root / "state db.sqlite"
            args = SimpleNamespace(
                config_root=str(config_root),
                git_root="",
                state_db=str(state_db),
                user_id="demo user #1",
                agent_id="shared agent",
                app_id="agent's memory",
                overwrite_env=False,
            )
            original_repo_root = bootstrap.REPO_ROOT
            bootstrap.REPO_ROOT = root
            try:
                bootstrap.write_env(args, memory_root)
            finally:
                bootstrap.REPO_ROOT = original_repo_root

            names = [
                "AGENT_MEMORY_ROOT",
                "AGENT_MEMORY_CONFIG_ROOT",
                "AGENT_MEMORY_STATE_DB",
                "AGENT_MEMORY_USER_ID",
                "AGENT_MEMORY_AGENT_ID",
                "AGENT_MEMORY_APP_ID",
            ]
            values = read_exported_values(root / ".env", names)
            self.assertEqual(values["AGENT_MEMORY_ROOT"], str(memory_root))
            self.assertEqual(values["AGENT_MEMORY_CONFIG_ROOT"], str(bootstrap.expand_path(str(config_root))))
            self.assertEqual(values["AGENT_MEMORY_STATE_DB"], str(bootstrap.expand_path(str(state_db))))
            self.assertEqual(values["AGENT_MEMORY_USER_ID"], args.user_id)
            self.assertEqual(values["AGENT_MEMORY_AGENT_ID"], args.agent_id)
            self.assertEqual(values["AGENT_MEMORY_APP_ID"], args.app_id)


if __name__ == "__main__":
    unittest.main()
