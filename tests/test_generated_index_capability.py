from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_generated_index_capability as capability
import agent_memory_closeout as closeout
import agent_memory_index as memory_index
import agent_memory_intent as memory_intent


class GeneratedIndexCapabilityTests(unittest.TestCase):
    @staticmethod
    def binding(root: Path) -> dict[str, str]:
        return {
            "transaction_id": "1" * 32,
            "actor": "test",
            "task_sha256": "2" * 64,
            "vault_root_sha256": hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest(),
            "git_head": "3" * 40,
            "index_base_sha256": "4" * 64,
            "full_vault_inputs_sha256": "5" * 64,
            "lease_fences_sha256": "6" * 64,
        }

    @staticmethod
    def state_db(root: Path) -> Path:
        path = root / "state.sqlite"
        with sqlite3.connect(path) as conn:
            memory_intent.ensure_schema(conn)
        if os.name != "nt":
            path.chmod(0o600)
        return path

    @staticmethod
    def register_transaction(
        state_db: Path,
        binding: dict[str, str],
        *,
        ttl_seconds: int = 30,
    ) -> None:
        with mock.patch.object(closeout, "STATE_DB", state_db):
            closeout._register_generated_index_closeout_transaction(
                transaction_binding=binding,
                ttl_seconds=ttl_seconds,
            )

    @staticmethod
    def git(root: Path, *args: str) -> str:
        completed = __import__("subprocess").run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def test_public_sync_api_cannot_modify_generated_index(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp, mock.patch.dict(
            os.environ,
            {
                capability.CAPABILITY_PATH_ENV: "",
                capability.CAPABILITY_TOKEN_ENV: "",
            },
            clear=False,
        ):
            root = Path(raw_tmp).resolve()
            vault = root / "vault"
            vault.mkdir()
            index = vault / "INDEX.md"
            original = b"<!-- agent-memory-generated-index:v1 -->\n# Original\n"
            index.write_bytes(original)
            with (
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
                mock.patch.object(memory_index, "CONFIG_ROOT", root / "config"),
                sqlite3.connect(":memory:") as conn,
                self.assertRaisesRegex(
                    capability.GeneratedIndexCapabilityError,
                    "GENERATED_FILE_READ_ONLY",
                ),
            ):
                memory_index.sync_generated_index(conn)
            self.assertEqual(index.read_bytes(), original)

    def test_candidate_output_cannot_overwrite_vault_or_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            vault = root / "vault"
            vault.mkdir()
            index = vault / "INDEX.md"
            original = "# Original\n"
            index.write_text(original, encoding="utf-8")
            existing = root / "existing.md"
            existing.write_text("keep", encoding="utf-8")
            with mock.patch.object(memory_index, "VAULT_ROOT", vault):
                with self.assertRaisesRegex(
                    capability.GeneratedIndexCapabilityError,
                    "GENERATED_FILE_READ_ONLY",
                ):
                    memory_index.write_generated_index_candidate(str(index), "# Candidate\n")
                with self.assertRaisesRegex(RuntimeError, "INDEX_CANDIDATE_OUTPUT_EXISTS"):
                    memory_index.write_generated_index_candidate(
                        str(existing), "# Candidate\n"
                    )
                created = memory_index.write_generated_index_candidate(
                    str(root / "new-candidate.md"), "# Candidate\n"
                )
            self.assertEqual(index.read_text(encoding="utf-8"), original)
            self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
            self.assertEqual(created.read_text(encoding="utf-8"), "# Candidate\n")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(created.stat().st_mode), 0o600)

    def test_child_full_vault_snapshot_detects_clean_file_race(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            vault = root / "vault"
            vault.mkdir()
            index = vault / "INDEX.md"
            index.write_text("# Index\n", encoding="utf-8")
            other = vault / "AGENTS.md"
            other.write_text("# Stable\n", encoding="utf-8")
            self.git(root, "init", "-q")
            self.git(root, "config", "user.name", "Snapshot Test")
            self.git(root, "config", "user.email", "snapshot@example.invalid")
            self.git(root, "add", "vault")
            self.git(root, "commit", "-qm", "base")
            with (
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
                mock.patch.object(memory_index, "GIT_ROOT", root),
            ):
                binding = self.binding(vault)
                binding["git_head"] = self.git(root, "rev-parse", "HEAD")
                binding["index_base_sha256"] = hashlib.sha256(index.read_bytes()).hexdigest()
                binding["full_vault_inputs_sha256"] = (
                    memory_index.full_vault_input_projection_sha256()
                )
                authorization = {"transaction_binding": binding}
                memory_index.verify_generated_index_transaction_snapshot(authorization)
                other.write_text("# Concurrent\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    capability.GeneratedIndexCapabilityError,
                    "GENERATED_INDEX_TRANSACTION_CHANGED",
                ):
                    memory_index.verify_generated_index_transaction_snapshot(authorization)

    def test_sync_rolls_back_when_second_scan_changes_generated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            vault = root / "vault"
            config_root = root / "config"
            state_db = root / "index.sqlite"
            vault.mkdir()
            index = vault / "INDEX.md"
            base = b"<!-- agent-memory-generated-index:v1 -->\n# Original\n"
            index.write_bytes(base)
            memory = vault / "AGENTS.md"
            stable = """---
memory_type: workflow
track: workflow
status: active
summary: Stable summary
---
# Rules
Stable body.
"""
            transient = stable.replace("Stable summary", "Transient summary")
            memory.write_text(stable, encoding="utf-8")
            binding = self.binding(vault)
            binding["index_base_sha256"] = hashlib.sha256(base).hexdigest()
            authorization = {"ok": True, "transaction_binding": binding}

            with (
                mock.patch.object(memory_index, "VAULT_ROOT", vault),
                mock.patch.object(memory_index, "CONFIG_ROOT", config_root),
                mock.patch.object(memory_index, "STATE_DB", state_db),
                sqlite3.connect(state_db) as conn,
            ):
                memory_index.init_db(conn)
                memory_index.scan(conn)
                stable_generated = memory_index.generated_index_markdown(conn)
                memory.write_text(transient, encoding="utf-8")
                memory_index.scan(conn)
                transient_generated = memory_index.generated_index_markdown(conn)
                memory.write_text(stable, encoding="utf-8")
                self.assertNotEqual(stable_generated, transient_generated)

                with (
                    mock.patch.object(
                        memory_index,
                        "verify_generated_index_transaction_snapshot",
                    ),
                    mock.patch.object(
                        memory_index,
                        "bind_expected_generated_index_sha256",
                    ),
                    mock.patch.object(
                        memory_index,
                        "bind_generated_index_recovery_evidence",
                    ),
                    self.assertRaisesRegex(
                        capability.GeneratedIndexCapabilityError,
                        "GENERATED_INDEX_POST_SCAN_DRIFT",
                    ),
                ):
                    memory_index.sync_generated_index(
                        conn,
                        consumed_capability=authorization,
                    )

                self.assertEqual(index.read_bytes(), base)
                self.assertEqual(
                    memory_index.generated_index_markdown(conn),
                    stable_generated,
                )

    @unittest.skipIf(os.name == "nt", "POSIX exchange race is covered by Windows ReplaceFile tests")
    def test_atomic_replace_race_preserves_unknown_concurrent_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            target = root / "INDEX.md"
            replacement = root / "replacement.md"
            base = b"base\n"
            generated = b"generated\n"
            concurrent = b"concurrent user edit\n"
            target.write_bytes(base)
            replacement.write_bytes(generated)
            original_exchange = memory_index._atomic_exchange_paths
            calls = 0

            def race_once(first: Path, second: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    target.write_bytes(concurrent)
                original_exchange(first, second)

            with (
                mock.patch.object(memory_index, "_atomic_exchange_paths", side_effect=race_once),
                self.assertRaisesRegex(OSError, "GENERATED_INDEX_BASE_CHANGED"),
            ):
                memory_index.conditional_atomic_replace(
                    target,
                    replacement,
                    expected_current_sha256=hashlib.sha256(base).hexdigest(),
                )
            self.assertEqual(target.read_bytes(), concurrent)
            self.assertEqual(replacement.read_bytes(), generated)

    def test_parent_rollback_conflict_preserves_later_user_edit(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            target = root / "INDEX.md"
            base = b"base\n"
            later = b"later user edit\n"
            target.write_bytes(later)
            snapshot = closeout.GeneratedIndexSnapshot(
                path=target,
                raw=base,
                mode=0o600,
                raw_sha256=hashlib.sha256(base).hexdigest(),
            )
            with mock.patch.object(closeout, "CONFIG_ROOT", root / "runtime"):
                result = closeout.restore_generated_index_snapshot(
                    snapshot,
                    expected_current_sha256=hashlib.sha256(b"generated\n").hexdigest(),
                    transaction_id="a" * 32,
                )
            self.assertFalse(result["ok"])
            self.assertEqual(result["detail"], "GENERATED_INDEX_ROLLBACK_CONFLICT")
            self.assertEqual(target.read_bytes(), later)

    def test_missing_environment_is_generated_file_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp, mock.patch.dict(
            os.environ,
            {
                capability.CAPABILITY_PATH_ENV: "",
                capability.CAPABILITY_TOKEN_ENV: "",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(
                capability.GeneratedIndexCapabilityError,
                "GENERATED_FILE_READ_ONLY",
            ):
                capability.consume_generated_index_capability_from_environment(
                    Path(raw_tmp),
                    state_db=Path(raw_tmp) / "missing-state.sqlite",
                )

    def test_capability_is_private_parent_bound_and_one_shot(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            config_root = Path(raw_tmp) / "config"
            state_db = self.state_db(Path(raw_tmp))
            self.register_transaction(
                state_db,
                self.binding(Path(raw_tmp) / "vault"),
            )
            issued = capability.issue_generated_index_capability(
                config_root,
                state_db=state_db,
                transaction_binding=self.binding(Path(raw_tmp) / "vault"),
                issuer_pid=os.getpid(),
                ttl_seconds=30,
            )
            path = Path(issued["path"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(issued["token"], path.read_text(encoding="utf-8"))

            result = capability.consume_generated_index_capability(
                config_root,
                state_db=state_db,
                capability_path=str(path),
                token=issued["token"],
                expected_transaction_binding=self.binding(Path(raw_tmp) / "vault"),
                expected_parent_pid=os.getpid(),
            )
            self.assertTrue(result["ok"])
            journal = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(journal["status"], "claimed")
            self.assertEqual(journal["consumer_pid"], os.getpid())
            capability.bind_expected_generated_index_sha256(
                state_db,
                result,
                generated_sha256="8" * 64,
            )
            capability.commit_generated_index_transaction(
                state_db,
                self.binding(Path(raw_tmp) / "vault"),
                generated_sha256="8" * 64,
                closeout_git_commit="9" * 40,
            )
            with sqlite3.connect(state_db) as conn:
                transaction = conn.execute(
                    "SELECT status, generated_sha256, closeout_git_commit "
                    "FROM generated_index_closeout_transactions "
                    "WHERE transaction_id=?",
                    (self.binding(Path(raw_tmp) / "vault")["transaction_id"],),
                ).fetchone()
            self.assertEqual(transaction, ("consumed", "8" * 64, "9" * 40))

            with self.assertRaisesRegex(
                capability.GeneratedIndexCapabilityError,
                "GENERATED_INDEX_CAPABILITY_INVALID",
            ):
                capability.consume_generated_index_capability(
                    config_root,
                    state_db=state_db,
                    capability_path=str(path),
                    token=issued["token"],
                    expected_transaction_binding=self.binding(Path(raw_tmp) / "vault"),
                    expected_parent_pid=os.getpid(),
                )

    def test_capability_without_durable_closeout_transaction_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            config_root = root / "config"
            state_db = self.state_db(root)
            binding = self.binding(root / "vault")
            with self.assertRaisesRegex(
                capability.GeneratedIndexCapabilityError,
                "GENERATED_INDEX_CLOSEOUT_TRANSACTION_MISSING",
            ):
                capability.issue_generated_index_capability(
                    config_root,
                    state_db=state_db,
                    transaction_binding=binding,
                    issuer_pid=os.getpid(),
                )
            self.register_transaction(state_db, binding)
            issued = capability.issue_generated_index_capability(
                config_root,
                state_db=state_db,
                transaction_binding=binding,
                issuer_pid=os.getpid(),
            )
            with sqlite3.connect(state_db) as conn:
                conn.execute(
                    "DELETE FROM generated_index_closeout_transactions WHERE transaction_id=?",
                    (binding["transaction_id"],),
                )
                conn.commit()
            with self.assertRaisesRegex(
                capability.GeneratedIndexCapabilityError,
                "GENERATED_INDEX_CLOSEOUT_TRANSACTION_MISSING",
            ):
                capability.consume_generated_index_capability(
                    config_root,
                    state_db=state_db,
                    capability_path=issued["path"],
                    token=issued["token"],
                    expected_transaction_binding=binding,
                    expected_parent_pid=os.getpid(),
                )

    def test_closeout_rejects_claimed_only_child_even_with_fake_success_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            config_root = Path(raw_tmp) / "config"
            state_db = self.state_db(Path(raw_tmp))
            transaction_binding = self.binding(Path(raw_tmp) / "vault")
            self.register_transaction(state_db, transaction_binding)
            captured: dict[str, str] = {}

            def fake_run(command, timeout=120, env=None, input_text=None):
                self.assertIsNotNone(env)
                captured["path"] = env[capability.CAPABILITY_PATH_ENV]
                captured["token"] = env[capability.CAPABILITY_TOKEN_ENV]
                self.assertNotIn(captured["token"], " ".join(command))
                capability.consume_generated_index_capability(
                    config_root,
                    state_db=state_db,
                    capability_path=captured["path"],
                    token=captured["token"],
                    expected_transaction_binding=transaction_binding,
                    expected_parent_pid=os.getpid(),
                )
                return {
                    "ok": True,
                    "returncode": 0,
                    "stdout": (
                        "generated_index_changed=0\n"
                        f"generated_index_path={Path(raw_tmp) / 'INDEX.md'}\n"
                        f"generated_index_sha256={'a' * 64}\n"
                    ),
                    "stderr": "",
                }

            with (
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "run_command", side_effect=fake_run),
            ):
                result = closeout.run_index(
                    type("Args", (), {"dry_run": False})(),
                    transaction_binding=transaction_binding,
                )
            self.assertFalse(result["ok"])
            self.assertEqual(result["detail"], "GENERATED_INDEX_DURABLE_READBACK_INVALID")
            self.assertEqual(
                json.loads(Path(captured["path"]).read_text(encoding="utf-8"))["status"],
                "claimed",
            )

    def test_closeout_accepts_only_durable_generated_bound_readback(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            config_root = root / "config"
            vault = root / "vault"
            vault.mkdir()
            index = vault / "INDEX.md"
            current = b"<!-- agent-memory-generated-index:v1 -->\n# Current\n"
            index.write_bytes(current)
            digest = hashlib.sha256(current).hexdigest()
            state_db = self.state_db(root)
            transaction_binding = self.binding(vault)
            transaction_binding["index_base_sha256"] = digest
            self.register_transaction(state_db, transaction_binding)

            def fake_run(command, timeout=120, env=None, input_text=None):
                authorization = capability.consume_generated_index_capability(
                    config_root,
                    state_db=state_db,
                    capability_path=env[capability.CAPABILITY_PATH_ENV],
                    token=env[capability.CAPABILITY_TOKEN_ENV],
                    expected_transaction_binding=transaction_binding,
                    expected_parent_pid=os.getpid(),
                )
                capability.bind_expected_generated_index_sha256(
                    state_db,
                    authorization,
                    generated_sha256=digest,
                )
                return {
                    "ok": True,
                    "returncode": 0,
                    "stdout": (
                        "generated_index_changed=0\n"
                        f"generated_index_path={index}\n"
                        f"generated_index_sha256={digest}\n"
                    ),
                    "stderr": "",
                }

            with (
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "VAULT_ROOT", vault),
                mock.patch.object(closeout, "run_command", side_effect=fake_run),
            ):
                result = closeout.run_index(
                    type("Args", (), {"dry_run": False})(),
                    transaction_binding=transaction_binding,
                )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["generated_index_transaction"]["status"], "generated_bound")

    def test_wrong_parent_and_expired_capabilities_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            config_root = Path(raw_tmp) / "config"
            state_db = self.state_db(Path(raw_tmp))
            self.register_transaction(
                state_db,
                self.binding(Path(raw_tmp) / "vault"),
            )
            wrong_parent = capability.issue_generated_index_capability(
                config_root,
                state_db=state_db,
                transaction_binding=self.binding(Path(raw_tmp) / "vault"),
                issuer_pid=os.getpid(),
            )
            with self.assertRaisesRegex(
                capability.GeneratedIndexCapabilityError,
                "GENERATED_INDEX_CAPABILITY_INVALID",
            ):
                capability.consume_generated_index_capability(
                    config_root,
                    state_db=state_db,
                    capability_path=wrong_parent["path"],
                    token=wrong_parent["token"],
                    expected_transaction_binding=self.binding(Path(raw_tmp) / "vault"),
                    expected_parent_pid=os.getpid() + 1,
                )

            expired_binding = self.binding(Path(raw_tmp) / "vault")
            expired_binding["transaction_id"] = "7" * 32
            self.register_transaction(state_db, expired_binding, ttl_seconds=1)
            expired = capability.issue_generated_index_capability(
                config_root,
                state_db=state_db,
                transaction_binding=expired_binding,
                issuer_pid=os.getpid(),
                ttl_seconds=1,
            )
            with self.assertRaisesRegex(
                capability.GeneratedIndexCapabilityError,
                "GENERATED_INDEX_CAPABILITY_EXPIRED",
            ):
                capability.consume_generated_index_capability(
                    config_root,
                    state_db=state_db,
                    capability_path=expired["path"],
                    token=expired["token"],
                    expected_transaction_binding=expired_binding,
                    expected_parent_pid=os.getpid(),
                    now_epoch=int(json.loads(Path(expired["path"]).read_text())["expires_at_epoch"]) + 1,
                )

    def test_parent_crash_after_publish_cas_restores_from_private_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            repo = root / "repo"
            vault = repo / "vault"
            config_root = root / "runtime"
            vault.mkdir(parents=True)
            base = b"<!-- agent-memory-generated-index:v1 -->\n# Base\n"
            generated = b"<!-- agent-memory-generated-index:v1 -->\n# Generated\n"
            index = vault / "INDEX.md"
            index.write_bytes(base)
            (vault / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "Recovery Test")
            self.git(repo, "config", "user.email", "recovery@example.invalid")
            self.git(repo, "add", "vault")
            self.git(repo, "commit", "-qm", "base")
            head = self.git(repo, "rev-parse", "HEAD")
            state_db = self.state_db(root)
            binding = self.binding(vault)
            binding["git_head"] = head
            binding["index_base_sha256"] = hashlib.sha256(base).hexdigest()
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
            ):
                closeout._register_generated_index_closeout_transaction(
                    transaction_binding=binding,
                )
            evidence_root = capability.generated_index_backup_directory(
                config_root,
                binding["transaction_id"],
            )
            replacement = evidence_root / "generated.md"
            replacement.write_bytes(generated)
            planned_evidence = (
                evidence_root / "previous.md" if os.name == "nt" else replacement
            )
            evidence = memory_index.conditional_atomic_replace(
                index,
                replacement,
                expected_current_sha256=hashlib.sha256(base).hexdigest(),
                evidence_path=planned_evidence,
            )
            digest = hashlib.sha256(generated).hexdigest()
            with sqlite3.connect(state_db) as conn:
                conn.execute(
                    "UPDATE generated_index_closeout_transactions "
                    "SET status='generated_bound', generated_sha256=?, issuer_pid=?, "
                    "consumer_pid=?, rollback_evidence_path=? WHERE transaction_id=?",
                    (
                        digest,
                        99_999_991,
                        99_999_992,
                        str(evidence),
                        binding["transaction_id"],
                    ),
                )
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                mock.patch.object(closeout, "VAULT_ROOT", vault),
                mock.patch.object(closeout, "REPO_ROOT", repo),
                mock.patch.object(
                    closeout,
                    "rescan_after_generated_index_restore",
                    return_value={"ok": True},
                ),
            ):
                recovered = closeout.recover_generated_index_transactions()
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["rolled_back"], 1)
            self.assertEqual(index.read_bytes(), base)
            self.assertTrue(
                any(
                    path.is_file() and path.read_bytes() == generated
                    for path in evidence_root.iterdir()
                )
            )
            self.assertFalse(any(path.name.startswith(".INDEX") for path in vault.iterdir()))
            with sqlite3.connect(state_db) as conn:
                status = conn.execute(
                    "SELECT status FROM generated_index_closeout_transactions "
                    "WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()[0]
            self.assertEqual(status, "rolled_back")

    def test_parent_crash_after_commit_recovers_consumed_commit_binding(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            repo = root / "repo"
            vault = repo / "vault"
            config_root = root / "runtime"
            vault.mkdir(parents=True)
            base = b"<!-- agent-memory-generated-index:v1 -->\n# Base\n"
            generated = b"<!-- agent-memory-generated-index:v1 -->\n# Generated\n"
            index = vault / "INDEX.md"
            index.write_bytes(base)
            (vault / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "Recovery Test")
            self.git(repo, "config", "user.email", "recovery@example.invalid")
            self.git(repo, "add", "vault")
            self.git(repo, "commit", "-qm", "base")
            base_head = self.git(repo, "rev-parse", "HEAD")
            state_db = self.state_db(root)
            binding = self.binding(vault)
            binding["git_head"] = base_head
            binding["index_base_sha256"] = hashlib.sha256(base).hexdigest()
            with mock.patch.object(closeout, "VAULT_ROOT", vault):
                binding["full_vault_inputs_sha256"] = (
                    closeout.full_vault_input_projection_sha256()
                )
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
            ):
                closeout._register_generated_index_closeout_transaction(
                    transaction_binding=binding,
                )
            index.write_bytes(generated)
            self.git(repo, "add", "vault/INDEX.md")
            self.git(repo, "commit", "-qm", "generated index")
            commit = self.git(repo, "rev-parse", "HEAD")
            digest = hashlib.sha256(generated).hexdigest()
            with sqlite3.connect(state_db) as conn:
                conn.execute(
                    "UPDATE generated_index_closeout_transactions "
                    "SET status='generated_bound', generated_sha256=?, issuer_pid=?, "
                    "consumer_pid=? WHERE transaction_id=?",
                    (digest, 99_999_993, 99_999_994, binding["transaction_id"]),
                )
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                mock.patch.object(closeout, "VAULT_ROOT", vault),
                mock.patch.object(closeout, "REPO_ROOT", repo),
            ):
                recovered = closeout.recover_generated_index_transactions()
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["committed"], 1)
            with sqlite3.connect(state_db) as conn:
                row = conn.execute(
                    "SELECT status, closeout_git_commit "
                    "FROM generated_index_closeout_transactions WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()
            self.assertEqual(row, ("consumed", commit))

    def test_recovery_binds_exact_commit_not_a_later_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            repo = root / "repo"
            vault = repo / "vault"
            config_root = root / "runtime"
            vault.mkdir(parents=True)
            base = b"<!-- agent-memory-generated-index:v1 -->\n# Base\n"
            generated = b"<!-- agent-memory-generated-index:v1 -->\n# Generated\n"
            index = vault / "INDEX.md"
            index.write_bytes(base)
            (vault / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "Recovery Test")
            self.git(repo, "config", "user.email", "recovery@example.invalid")
            self.git(repo, "add", "vault")
            self.git(repo, "commit", "-qm", "base")
            base_head = self.git(repo, "rev-parse", "HEAD")
            state_db = self.state_db(root)
            binding = self.binding(vault)
            binding["git_head"] = base_head
            binding["index_base_sha256"] = hashlib.sha256(base).hexdigest()
            with mock.patch.object(closeout, "VAULT_ROOT", vault):
                binding["full_vault_inputs_sha256"] = closeout.full_vault_input_projection_sha256()
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
            ):
                closeout._register_generated_index_closeout_transaction(
                    transaction_binding=binding,
                )
            index.write_bytes(generated)
            self.git(repo, "add", "vault/INDEX.md")
            self.git(repo, "commit", "-qm", "exact generated index")
            exact_commit = self.git(repo, "rev-parse", "HEAD")
            (repo / "later.txt").write_text("later\n", encoding="utf-8")
            self.git(repo, "add", "later.txt")
            self.git(repo, "commit", "-qm", "later unrelated commit")
            later_head = self.git(repo, "rev-parse", "HEAD")
            digest = hashlib.sha256(generated).hexdigest()
            with sqlite3.connect(state_db) as conn:
                conn.execute(
                    "UPDATE generated_index_closeout_transactions "
                    "SET status='generated_bound', generated_sha256=?, issuer_pid=?, "
                    "consumer_pid=? WHERE transaction_id=?",
                    (digest, 99_999_981, 99_999_982, binding["transaction_id"]),
                )
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                mock.patch.object(closeout, "VAULT_ROOT", vault),
                mock.patch.object(closeout, "REPO_ROOT", repo),
            ):
                recovered = closeout.recover_generated_index_transactions()
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["committed"], 1)
            with sqlite3.connect(state_db) as conn:
                stored = conn.execute(
                    "SELECT closeout_git_commit FROM generated_index_closeout_transactions "
                    "WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()[0]
            self.assertEqual(stored, exact_commit)
            self.assertNotEqual(stored, later_head)

    def test_recovery_rejects_descendant_with_different_full_vault_projection(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            repo = root / "repo"
            vault = repo / "vault"
            config_root = root / "runtime"
            vault.mkdir(parents=True)
            base = b"<!-- agent-memory-generated-index:v1 -->\n# Base\n"
            generated = b"<!-- agent-memory-generated-index:v1 -->\n# Generated\n"
            index = vault / "INDEX.md"
            rules = vault / "AGENTS.md"
            index.write_bytes(base)
            rules.write_text("# Bound rules\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "Recovery Test")
            self.git(repo, "config", "user.email", "recovery@example.invalid")
            self.git(repo, "add", "vault")
            self.git(repo, "commit", "-qm", "base")
            base_head = self.git(repo, "rev-parse", "HEAD")
            state_db = self.state_db(root)
            binding = self.binding(vault)
            binding["git_head"] = base_head
            binding["index_base_sha256"] = hashlib.sha256(base).hexdigest()
            with mock.patch.object(closeout, "VAULT_ROOT", vault):
                binding["full_vault_inputs_sha256"] = closeout.full_vault_input_projection_sha256()
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
            ):
                closeout._register_generated_index_closeout_transaction(
                    transaction_binding=binding,
                )
            evidence_root = capability.generated_index_backup_directory(
                config_root,
                binding["transaction_id"],
            )
            evidence = evidence_root / "previous.md"
            evidence.write_bytes(base)
            index.write_bytes(generated)
            rules.write_text("# Different later rules\n", encoding="utf-8")
            self.git(repo, "add", "vault")
            self.git(repo, "commit", "-qm", "unrelated mismatched snapshot")
            digest = hashlib.sha256(generated).hexdigest()
            with sqlite3.connect(state_db) as conn:
                conn.execute(
                    "UPDATE generated_index_closeout_transactions "
                    "SET status='generated_bound', generated_sha256=?, issuer_pid=?, "
                    "consumer_pid=?, rollback_evidence_path=? WHERE transaction_id=?",
                    (
                        digest,
                        99_999_971,
                        99_999_972,
                        str(evidence),
                        binding["transaction_id"],
                    ),
                )
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                mock.patch.object(closeout, "VAULT_ROOT", vault),
                mock.patch.object(closeout, "REPO_ROOT", repo),
                mock.patch.object(
                    closeout,
                    "rescan_after_generated_index_restore",
                    return_value={"ok": True},
                ),
            ):
                recovered = closeout.recover_generated_index_transactions()
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["committed"], 0)
            self.assertEqual(recovered["rolled_back"], 1)
            self.assertEqual(index.read_bytes(), base)
            with sqlite3.connect(state_db) as conn:
                status = conn.execute(
                    "SELECT status FROM generated_index_closeout_transactions "
                    "WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()[0]
            self.assertEqual(status, "rolled_back")

    def test_transient_failed_recovery_resolves_after_base_rescan_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            repo = root / "repo"
            vault = repo / "vault"
            config_root = root / "runtime"
            vault.mkdir(parents=True)
            base = b"base\n"
            generated = b"generated\n"
            index = vault / "INDEX.md"
            index.write_bytes(base)
            (vault / "AGENTS.md").write_text("stable\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "Recovery Test")
            self.git(repo, "config", "user.email", "recovery@example.invalid")
            self.git(repo, "add", "vault")
            self.git(repo, "commit", "-qm", "base")
            state_db = self.state_db(root)
            binding = self.binding(vault)
            binding["git_head"] = self.git(repo, "rev-parse", "HEAD")
            binding["index_base_sha256"] = hashlib.sha256(base).hexdigest()
            with mock.patch.object(closeout, "VAULT_ROOT", vault):
                binding["full_vault_inputs_sha256"] = closeout.full_vault_input_projection_sha256()
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
            ):
                closeout._register_generated_index_closeout_transaction(
                    transaction_binding=binding,
                )
            evidence_root = capability.generated_index_backup_directory(
                config_root,
                binding["transaction_id"],
            )
            evidence = evidence_root / "previous.md"
            evidence.write_bytes(base)
            index.write_bytes(generated)
            digest = hashlib.sha256(generated).hexdigest()
            with sqlite3.connect(state_db) as conn:
                conn.execute(
                    "UPDATE generated_index_closeout_transactions "
                    "SET status='generated_bound', generated_sha256=?, issuer_pid=?, "
                    "consumer_pid=?, rollback_evidence_path=? WHERE transaction_id=?",
                    (
                        digest,
                        99_999_961,
                        99_999_962,
                        str(evidence),
                        binding["transaction_id"],
                    ),
                )
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                mock.patch.object(closeout, "VAULT_ROOT", vault),
                mock.patch.object(closeout, "REPO_ROOT", repo),
                mock.patch.object(
                    closeout,
                    "rescan_after_generated_index_restore",
                    return_value={"ok": False, "detail": "transient_lock"},
                ),
            ):
                first = closeout.recover_generated_index_transactions()
            self.assertEqual(first["failed"], 1)
            self.assertEqual(index.read_bytes(), base)
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                mock.patch.object(closeout, "VAULT_ROOT", vault),
                mock.patch.object(closeout, "REPO_ROOT", repo),
                mock.patch.object(
                    closeout,
                    "rescan_after_generated_index_restore",
                    return_value={"ok": True},
                ),
            ):
                second = closeout.recover_generated_index_transactions()
            self.assertTrue(second["ok"], second)
            self.assertEqual(second["rolled_back"], 1)
            with sqlite3.connect(state_db) as conn:
                status, reason, failed_at = conn.execute(
                    "SELECT status, failure_reason, failure_at_epoch "
                    "FROM generated_index_closeout_transactions WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()
            self.assertEqual(status, "rolled_back")
            self.assertEqual(reason, "GENERATED_INDEX_ROLLBACK_REINDEX_FAILED")
            self.assertGreater(int(failed_at), 0)

    def test_recovery_conflict_stays_failed_and_preserves_unknown_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp).resolve()
            repo = root / "repo"
            vault = repo / "vault"
            config_root = root / "runtime"
            vault.mkdir(parents=True)
            base = b"base\n"
            generated = b"generated\n"
            concurrent = b"later user bytes\n"
            index = vault / "INDEX.md"
            index.write_bytes(base)
            (vault / "AGENTS.md").write_text("stable\n", encoding="utf-8")
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "Recovery Test")
            self.git(repo, "config", "user.email", "recovery@example.invalid")
            self.git(repo, "add", "vault")
            self.git(repo, "commit", "-qm", "base")
            state_db = self.state_db(root)
            binding = self.binding(vault)
            binding["git_head"] = self.git(repo, "rev-parse", "HEAD")
            binding["index_base_sha256"] = hashlib.sha256(base).hexdigest()
            with mock.patch.object(closeout, "VAULT_ROOT", vault):
                binding["full_vault_inputs_sha256"] = (
                    closeout.full_vault_input_projection_sha256()
                )
            with (
                mock.patch.object(closeout, "STATE_DB", state_db),
                mock.patch.object(closeout, "CONFIG_ROOT", config_root),
            ):
                closeout._register_generated_index_closeout_transaction(
                    transaction_binding=binding,
                )
            index.write_bytes(concurrent)
            digest = hashlib.sha256(generated).hexdigest()
            with sqlite3.connect(state_db) as conn:
                conn.execute(
                    "UPDATE generated_index_closeout_transactions "
                    "SET status='generated_bound', generated_sha256=?, issuer_pid=?, "
                    "consumer_pid=? WHERE transaction_id=?",
                    (digest, 99_999_951, 99_999_952, binding["transaction_id"]),
                )

            def recover() -> dict[str, object]:
                with (
                    mock.patch.object(closeout, "STATE_DB", state_db),
                    mock.patch.object(closeout, "CONFIG_ROOT", config_root),
                    mock.patch.object(closeout, "VAULT_ROOT", vault),
                    mock.patch.object(closeout, "REPO_ROOT", repo),
                ):
                    return closeout.recover_generated_index_transactions()

            first = recover()
            self.assertFalse(first["ok"], first)
            self.assertEqual(first["failed"], 1)
            self.assertEqual(index.read_bytes(), concurrent)
            second = recover()
            self.assertFalse(second["ok"], second)
            self.assertEqual(second["blocked"], 1)
            self.assertEqual(index.read_bytes(), concurrent)
            with sqlite3.connect(state_db) as conn:
                status, reason, failed_at = conn.execute(
                    "SELECT status, failure_reason, failure_at_epoch "
                    "FROM generated_index_closeout_transactions WHERE transaction_id=?",
                    (binding["transaction_id"],),
                ).fetchone()
            self.assertEqual(status, "failed")
            self.assertEqual(reason, "GENERATED_INDEX_RECOVERY_CONFLICT")
            self.assertGreater(int(failed_at), 0)

    @unittest.skipIf(os.name == "nt", "Windows symlink creation requires host policy support")
    def test_symlink_or_outside_capability_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            config_root = root / "config"
            state_db = self.state_db(root)
            self.register_transaction(state_db, self.binding(root / "vault"))
            issued = capability.issue_generated_index_capability(
                config_root,
                state_db=state_db,
                transaction_binding=self.binding(root / "vault"),
                issuer_pid=os.getpid(),
            )
            link = root / "capability-link.json"
            link.symlink_to(Path(issued["path"]))
            for path in (link, root / "outside.json"):
                if path.name == "outside.json":
                    path.write_text("{}", encoding="utf-8")
                    os.chmod(path, 0o600)
                with self.assertRaisesRegex(
                    capability.GeneratedIndexCapabilityError,
                    "GENERATED_INDEX_CAPABILITY_INVALID",
                ):
                    capability.consume_generated_index_capability(
                        config_root,
                        state_db=state_db,
                        capability_path=str(path),
                        token=issued["token"],
                        expected_transaction_binding=self.binding(root / "vault"),
                        expected_parent_pid=os.getpid(),
                    )


if __name__ == "__main__":
    unittest.main()
