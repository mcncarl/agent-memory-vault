from __future__ import annotations

import json
import contextlib
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_state as memory_state
from agent_memory_state import (
    StateSecurityError,
    secure_append_text,
    secure_sqlite_connect,
    sqlite_permission_report,
)
from tests.state_fixture import initialize_full_state


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


class StatePermissionTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX file modes and symlinks are not the Windows security model")
    def test_secure_append_creates_private_log_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            log_path = root / "logs" / "closeout.jsonl"
            secure_append_text(log_path, '{"status":"ok"}\n')
            secure_append_text(log_path, '{"status":"warning"}\n')
            self.assertEqual(mode(root / "logs"), 0o700)
            self.assertEqual(mode(log_path), 0o600)
            self.assertEqual(len(log_path.read_text(encoding="utf-8").splitlines()), 2)

            target = root / "target.log"
            target.write_text("existing\n", encoding="utf-8")
            link = root / "logs" / "linked.jsonl"
            link.symlink_to(target)
            with self.assertRaises(StateSecurityError):
                secure_append_text(link, "blocked\n")

    def test_secure_connect_creates_private_tree_database_and_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            database = root / "new" / "nested" / "state.sqlite"
            connection = secure_sqlite_connect(
                database,
                pragmas=("PRAGMA journal_mode=WAL",),
            )
            connection.execute("CREATE TABLE sample(value TEXT)")
            connection.execute("INSERT INTO sample VALUES ('ok')")
            connection.commit()

            if os.name != "nt":
                self.assertEqual(mode(root / "new"), 0o700)
                self.assertEqual(mode(root / "new" / "nested"), 0o700)
                self.assertEqual(mode(database), 0o600)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{database}{suffix}")
                self.assertTrue(sidecar.is_file())
                if os.name != "nt":
                    self.assertEqual(mode(sidecar), 0o600)
            connection.close()

    @unittest.skipIf(os.name == "nt", "symlink behavior requires explicit Windows privileges")
    def test_secure_connect_rejects_database_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            target = root / "target.sqlite"
            with contextlib.closing(sqlite3.connect(target)) as connection, connection:
                connection.execute("CREATE TABLE sample(value TEXT)")
            link = root / "state.sqlite"
            link.symlink_to(target)
            with self.assertRaises(StateSecurityError):
                secure_sqlite_connect(link)

    @unittest.skipIf(os.name == "nt", "POSIX mode drift is not meaningful on Windows")
    def test_normal_connect_repairs_existing_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with contextlib.closing(sqlite3.connect(database)) as connection, connection:
                connection.execute("CREATE TABLE sample(value TEXT)")
            database.chmod(0o644)
            self.assertFalse(sqlite_permission_report(database)["ok"])
            connection = secure_sqlite_connect(database)
            connection.close()
            self.assertEqual(mode(database), 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX mode drift is not meaningful on Windows")
    def test_doctor_fails_mode_drift_without_repairing_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            runtime = root / "runtime"
            state_db = runtime / "state.sqlite"
            env = os.environ.copy()
            env.update(
                {
                    "AGENT_MEMORY_ROOT": str(REPO_ROOT / "templates" / "vault"),
                    "AGENT_MEMORY_GIT_ROOT": str(REPO_ROOT),
                    "AGENT_MEMORY_CONFIG_ROOT": str(runtime),
                    "AGENT_MEMORY_STATE_DB": str(state_db),
                }
            )
            initialize_full_state(state_db)
            indexed = subprocess.run(
                [sys.executable, str(SCRIPTS / "agent_memory_index.py"), "--init", "--scan"],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(indexed.returncode, 0, indexed.stdout + indexed.stderr)
            state_db.chmod(0o644)

            checked = subprocess.run(
                [sys.executable, str(SCRIPTS / "agent_memory_doctor.py"), "--json"],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(checked.returncode, 2, checked.stdout + checked.stderr)
            payload = json.loads(checked.stdout)
            permission_check = next(
                item for item in payload["checks"] if item["name"] == "state_db_permissions"
            )
            self.assertEqual(permission_check["status"], "fail")
            self.assertEqual(mode(state_db), 0o644)

    def test_secure_connection_context_closes_the_handle(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with secure_sqlite_connect(database) as connection:
                connection.execute("CREATE TABLE sample(value TEXT)")
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_read_only_connect_falls_back_to_query_only_rw_for_wal_open_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "state.sqlite"
            with secure_sqlite_connect(
                database,
                pragmas=("PRAGMA journal_mode=WAL",),
            ) as writer:
                writer.execute("CREATE TABLE sample(value TEXT)")
                writer.execute("INSERT INTO sample VALUES ('ok')")
                writer.commit()

                real_connect = sqlite3.connect
                real_execute = memory_state.PrivateSQLiteConnection.execute
                failed_schema_probe = False

                def fail_first_schema_probe(connection, statement, *args, **kwargs):
                    nonlocal failed_schema_probe
                    if not failed_schema_probe and statement.strip().upper() == "PRAGMA SCHEMA_VERSION":
                        failed_schema_probe = True
                        raise sqlite3.OperationalError("unable to open database file")
                    return real_execute(connection, statement, *args, **kwargs)

                with (
                    mock.patch.object(memory_state.sqlite3, "connect", wraps=real_connect) as connect_mock,
                    mock.patch.object(
                        memory_state.PrivateSQLiteConnection,
                        "execute",
                        new=fail_first_schema_probe,
                    ),
                ):
                    with secure_sqlite_connect(
                        database,
                        read_only=True,
                        pragmas=("PRAGMA query_only=OFF",),
                    ) as reader:
                        self.assertEqual(reader.execute("PRAGMA query_only").fetchone()[0], 1)
                        self.assertEqual(reader.execute("SELECT value FROM sample").fetchone()[0], "ok")
                        with self.assertRaises(sqlite3.OperationalError):
                            reader.execute("UPDATE sample SET value='changed'")
                self.assertEqual(writer.execute("SELECT value FROM sample").fetchone()[0], "ok")

                targets = [str(call.args[0]) for call in connect_mock.call_args_list]
                self.assertEqual(len(targets), 2)
                self.assertTrue(targets[0].endswith("?mode=ro"), targets)
                self.assertTrue(targets[1].endswith("?mode=rw"), targets)
                self.assertTrue(database.is_file())

    def test_read_only_connect_never_creates_a_missing_database(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            database = Path(raw_root).resolve() / "missing.sqlite"
            with self.assertRaises(StateSecurityError):
                secure_sqlite_connect(database, read_only=True)
            self.assertFalse(database.exists())


if __name__ == "__main__":
    unittest.main()
