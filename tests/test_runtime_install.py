from __future__ import annotations

import json
import os
import subprocess
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install_runtime.py"


class RuntimeInstallTests(unittest.TestCase):
    def test_installed_runtime_can_retrieve_revalidated_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            runtime = root / "runtime"
            vault = root / "vault"
            memory = vault / "项目" / "example.md"
            memory.parent.mkdir(parents=True)
            memory.write_text(
                "---\n"
                "memory_type: project\n"
                "track: project\n"
                "app_id: yichen-content-studio\n"
                "project_id: example-app\n"
                "status: active\n"
                "agent_scope: shared\n"
                "verified_at: 2026-08-08\n"
                "---\n\n"
                "# Example\n\n"
                "runtimeprobe\n\n"
                "## 当前有效摘要\n\n"
                "Installed runtime retrieval works.\n",
                encoding="utf-8",
            )
            installed = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(runtime), "--json"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            config = runtime / "config" / "agent-memory.toml"
            config.write_text(
                f"memory_root = {json.dumps(str(vault), ensure_ascii=False)}\n"
                f"git_root = {json.dumps(str(vault), ensure_ascii=False)}\n"
                f"state_db = {json.dumps(str(runtime / 'state.sqlite'), ensure_ascii=False)}\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                config.chmod(0o600)
            indexed = subprocess.run(
                [sys.executable, str(runtime / "scripts" / "agent_memory_index.py"), "--init", "--scan"],
                cwd=runtime,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(indexed.returncode, 0, indexed.stdout + indexed.stderr)
            private_query = "runtimeprobe"
            retrieve_command = [
                sys.executable,
                str(runtime / "scripts" / "memoryctl"),
                "--actor",
                "yichen-content-studio",
                "retrieve",
                "--json",
            ]
            self.assertNotIn(private_query, retrieve_command)
            retrieved = subprocess.run(
                retrieve_command,
                cwd=runtime,
                input=json.dumps(
                    {
                        "schema_version": 1,
                        "query": private_query,
                        "app_id": "yichen-content-studio",
                        "project_id": "example-app",
                    }
                ),
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(retrieved.returncode, 0, retrieved.stdout + retrieved.stderr)
            payload = json.loads(retrieved.stdout)
            self.assertEqual(payload["result_count"], 1)
            self.assertEqual(payload["results"][0]["relative_path"], "项目/example.md")
            self.assertEqual(payload["results"][0]["excerpt"], "Installed runtime retrieval works.")

    def test_install_is_idempotent_and_preserves_local_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            scripts = root / "scripts"
            scripts.mkdir(parents=True)
            local_adapter = scripts / "local_adapter.py"
            local_adapter.write_text("LOCAL = True\n", encoding="utf-8")

            first = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--json"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            payload = json.loads(first.stdout)
            self.assertIn("memoryctl", payload["changed"])
            self.assertIn("requirements-vector.lock", payload["changed"])
            self.assertTrue(local_adapter.exists())
            self.assertTrue((root / "requirements-vector.lock").is_file())
            self.assertTrue((root / "benchmarks" / "public-sample.json").is_file())
            self.assertTrue((root / "benchmarks" / "public-policy-reconcile.json").is_file())
            self.assertTrue((root / "benchmarks" / "public-policy-safety.json").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_safety.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_policy_benchmark.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_retrieve.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_write.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_state.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_lock.py").is_file())
            self.assertTrue((root / "scripts" / "install-windows.ps1").is_file())
            self.assertTrue((root / "templates" / "vault" / "AGENTS.md").is_file())
            self.assertEqual(
                (root / "templates" / "vault" / ".gitignore").read_text(encoding="utf-8"),
                ".obsidian/\n",
            )
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                self.assertEqual(
                    stat.S_IMODE((root / "config" / "runtime-manifest.json").stat().st_mode),
                    0o600,
                )

            verify = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--verify", "--json"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            self.assertTrue(json.loads(verify.stdout)["ok"])

            second = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--json"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertEqual(json.loads(second.stdout)["changed"], [])
            self.assertEqual(local_adapter.read_text(encoding="utf-8"), "LOCAL = True\n")

    def test_install_repairs_config_and_existing_sqlite_modes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            config_dir = root / "config"
            config_dir.mkdir()
            config_file = config_dir / "agent-memory.toml"
            config_file.write_text("memory_root = '/tmp/example'\n", encoding="utf-8")
            state_db = root / "state.sqlite"
            connection = sqlite3.connect(state_db)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE sample(value TEXT)")
            connection.execute("INSERT INTO sample VALUES ('ok')")
            connection.commit()
            for path in (root, config_file, state_db, Path(f"{state_db}-wal"), Path(f"{state_db}-shm")):
                path.chmod(0o755 if path == root else 0o644)

            installed = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--json"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(config_file.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(state_db.stat().st_mode), 0o600)
                for suffix in ("-wal", "-shm"):
                    self.assertEqual(stat.S_IMODE(Path(f"{state_db}{suffix}").stat().st_mode), 0o600)
            # SQLite may checkpoint and remove WAL sidecars when the final
            # connection closes, so inspect their repaired modes first.
            connection.close()

    def test_installed_runtime_can_bootstrap_a_clean_git_vault(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            runtime = root / "runtime with spaces"
            vault = root / "vault with spaces"
            installed = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(runtime), "--json"],
                cwd=REPO_ROOT,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)

            bootstrap = subprocess.run(
                [
                    sys.executable,
                    str(runtime / "scripts" / "bootstrap.py"),
                    "--memory-root",
                    str(vault),
                ],
                cwd=runtime,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(bootstrap.returncode, 0, bootstrap.stdout + bootstrap.stderr)
            head = subprocess.run(
                ["git", "-C", str(vault), "rev-parse", "--verify", "HEAD"],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(head.returncode, 0, head.stdout + head.stderr)
            (vault / ".obsidian").mkdir()
            (vault / ".obsidian" / "workspace.json").write_text("{}\n", encoding="utf-8")
            status = subprocess.run(
                ["git", "-C", str(vault), "status", "--porcelain"],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(status.returncode, 0, status.stdout + status.stderr)
            self.assertEqual(status.stdout, "")


if __name__ == "__main__":
    unittest.main()
