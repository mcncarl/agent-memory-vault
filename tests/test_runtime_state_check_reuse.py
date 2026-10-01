from __future__ import annotations

import concurrent.futures
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import agent_memory_env as env


class StateCheckReuseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name).resolve() / "state.sqlite"
        self.connection = sqlite3.connect(self.path)
        self.addCleanup(self.connection.close)
        self.connection.execute("CREATE TABLE proof(value TEXT)")
        self.connection.commit()
        self.scans = []
        self.connection.set_trace_callback(self.trace)
        env._reset_state_check_cache()
        self.addCleanup(env._reset_state_check_cache)

    def trace(self, query):
        if query.upper() == "PRAGMA QUICK_CHECK":
            self.scans.append(query)

    def check(self):
        return env._runtime_state_quick_check(
            self.connection, self.path,
            opened_generation=env._state_check_fingerprint(self.path),
        )

    @unittest.skipUnless(os.name == "posix", "POSIX-only bounded reuse")
    def test_unchanged_generation_reuses_only_successful_scan(self):
        with mock.patch.object(env.time, "monotonic", return_value=10):
            self.assertEqual(self.check(), "ok")
            self.assertEqual(self.check(), "ok")
        self.assertEqual(len(self.scans), 1)

    def test_commit_invalidates_scan(self):
        with mock.patch.object(env.time, "monotonic", return_value=10):
            self.check()
            self.connection.execute("INSERT INTO proof VALUES ('changed')")
            self.connection.commit()
            self.check()
        self.assertEqual(len(self.scans), 2)

    def test_wal_commit_and_checkpoint_invalidate_scan(self):
        self.connection.execute("PRAGMA journal_mode=WAL")
        with mock.patch.object(env.time, "monotonic", return_value=10):
            self.check()
            self.connection.execute("INSERT INTO proof VALUES ('changed')")
            self.connection.commit()
            self.check()
            self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.check()
        self.assertEqual(len(self.scans), 3)

    def test_same_size_backdated_edit_and_replacement_change_fingerprint(self):
        before = env._state_check_fingerprint(self.path)
        metadata = self.path.stat()
        with self.path.open("r+b") as handle:
            handle.seek(-1, os.SEEK_END)
            byte = handle.read(1)
            handle.seek(-1, os.SEEK_END)
            handle.write(byte)
        os.utime(self.path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        self.assertNotEqual(before, env._state_check_fingerprint(self.path))
        before = env._state_check_fingerprint(self.path)
        replacement = self.path.with_suffix(".replacement")
        replacement.write_bytes(self.path.read_bytes())
        replacement.replace(self.path)
        self.assertNotEqual(before, env._state_check_fingerprint(self.path))

    @unittest.skipUnless(os.name == "posix", "POSIX-only bounded reuse")
    def test_ttl_and_backwards_clock_force_scan(self):
        for now in (10, 11, 9):
            with mock.patch.object(env.time, "monotonic", return_value=now):
                self.check()
        self.assertEqual(len(self.scans), 3)

    @unittest.skipUnless(os.name == "posix", "POSIX-only bounded reuse")
    def test_slow_scan_is_not_cached(self):
        with mock.patch.object(env.time, "monotonic", side_effect=[10, 10, 11.1]):
            self.check()
        self.assertIsNone(env._state_check_cache)

    def test_active_transaction_is_never_reused(self):
        self.check()
        self.connection.execute("BEGIN")
        self.check()
        self.check()
        self.assertEqual(len(self.scans), 3)

    @unittest.skipUnless(os.name == "posix", "POSIX-only bounded reuse")
    def test_failed_or_raised_check_is_never_cached(self):
        fake = mock.Mock(in_transaction=False)
        fake.execute.return_value.fetchone.return_value = ("corruption",)
        generation = env._state_check_fingerprint(self.path)
        self.assertEqual(env._runtime_state_quick_check(fake, self.path, opened_generation=generation), "corruption")
        self.assertIsNone(env._state_check_cache)
        fake.execute.side_effect = sqlite3.DatabaseError("corruption")
        with self.assertRaises(sqlite3.DatabaseError):
            env._runtime_state_quick_check(fake, self.path, opened_generation=generation)
        self.assertIsNone(env._state_check_cache)

    @unittest.skipUnless(os.name == "posix", "POSIX-only bounded reuse")
    def test_generation_change_during_scan_is_never_cached(self):
        with mock.patch.object(env, "_state_check_fingerprint", side_effect=[("before",), ("before",), ("after",)]):
            self.check()
        self.assertIsNone(env._state_check_cache)

    def test_generation_replaced_after_open_is_not_reused_or_published(self):
        self.check()
        env._runtime_state_quick_check(self.connection, self.path, opened_generation=("old",))
        self.assertEqual(len(self.scans), 2)
        self.assertIsNone(env._state_check_cache)

    def test_missing_open_generation_never_reuses_proof(self):
        self.check()
        env._runtime_state_quick_check(self.connection, self.path)
        self.assertEqual(len(self.scans), 2)

    @unittest.skipUnless(os.name == "posix", "POSIX symlinks")
    def test_unsafe_sidecar_rejected_even_with_cached_scan(self):
        self.check()
        Path(str(self.path) + "-wal").symlink_to(self.path)
        with self.assertRaises(env.StateSecurityError):
            self.check()

    def test_config_reset_and_fork_reset_drop_proof(self):
        self.check()
        env.reset_config_cache()
        self.assertIsNone(env._state_check_cache)
        self.check()
        env._reset_state_check_cache()
        self.assertIsNone(env._state_check_cache)

    @unittest.skipUnless(os.name == "posix", "POSIX-only bounded reuse")
    def test_parallel_checks_singleflight(self):
        barrier = threading.Barrier(4)

        def check():
            with sqlite3.connect(self.path) as connection:
                connection.set_trace_callback(self.trace)
                barrier.wait(timeout=5)
                return env._runtime_state_quick_check(
                    connection, self.path,
                    opened_generation=env._state_check_fingerprint(self.path),
                )

        with mock.patch.object(env.time, "monotonic", return_value=10):
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                self.assertEqual(list(executor.map(lambda _: check(), range(4))), ["ok"] * 4)
        self.assertEqual(len(self.scans), 1)

    def test_non_posix_always_scans(self):
        generation = env._state_check_fingerprint(self.path)
        with mock.patch.object(env.os, "name", "nt"):
            for _ in range(2):
                env._runtime_state_quick_check(
                    self.connection, self.path, opened_generation=generation,
                )
        self.assertEqual(len(self.scans), 2)

    def test_readiness_schema_validation_is_not_cached(self):
        from tests.state_fixture import initialize_full_state

        root = Path(self.directory.name).resolve()
        state_path = root / "full.sqlite"
        initialize_full_state(state_path)
        state_path.chmod(0o600)
        with (
            mock.patch.object(env, "RUNTIME_ROOT", root),
            mock.patch.dict(os.environ, {
                "AGENT_MEMORY_ROOT": str(root), "AGENT_MEMORY_GIT_ROOT": str(root),
                "AGENT_MEMORY_STATE_DB": str(state_path),
                "AGENT_MEMORY_CONFIG_FILE": str(root / "unused.toml"),
            }, clear=True),
        ):
            env.reset_config_cache()
            ready = env._runtime_state_status(require_toml=False)
            self.assertTrue(ready["ok"], ready)
            with sqlite3.connect(state_path) as connection:
                connection.execute("UPDATE meta SET value='3' WHERE key='agent_memory_state_schema_version'")
            result = env._runtime_state_status(require_toml=False)
            self.assertFalse(result["ok"])
            self.assertEqual(result["reason_code"], "RUNTIME_STATE_SCHEMA_MISMATCH")
        env.reset_config_cache()


if __name__ == "__main__":
    unittest.main()
