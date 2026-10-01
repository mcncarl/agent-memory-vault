from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install_runtime.py"
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

import install_runtime as runtime_installer


def managed_python(runtime: Path) -> Path:
    return (
        runtime / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else runtime / ".venv" / "bin" / "python"
    )


def isolated_runtime_env(root: Path) -> dict[str, str]:
    home = root / "test-home"
    home.mkdir(parents=True, exist_ok=True)
    # The isolation runner deliberately exports a temporary Agent Memory
    # source/config/state tuple for ordinary tests.  A nested installed-Runtime
    # test is a separate trust boundary and must not inherit any of those
    # pointers (or an actor/session identity) into its subprocesses.
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AGENT_MEMORY_")
        and key
        not in {
            "MEMORY_ACTOR",
            "CODEX_THREAD_ID",
            "CLAUDE_SESSION_ID",
            "CLAUDE_CODE_SESSION_ID",
        }
    }
    environment["HOME"] = str(home)
    environment["USERPROFILE"] = str(home)
    return environment


def install_deferred_scheduler(
    runtime: Path,
    *,
    environment: dict[str, str],
    backup_dir: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(runtime / "scripts" / "install_audit_launchagent.py"),
            "--apply",
            "--runtime-root",
            str(runtime),
            "--python",
            str(managed_python(runtime)),
            "--backup-dir",
            str(backup_dir),
            "--defer-load",
            "--json",
        ],
        cwd=runtime,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)


def synchronize_and_commit_generated_index(
    runtime: Path,
    vault: Path,
    *,
    environment: dict[str, str],
) -> None:
    """Build the production generated INDEX inside an installing test Runtime.

    The publish preflight deliberately treats INDEX.md as immutable input; it
    must not silently repair formal Vault content.  Test fixtures therefore
    perform the same generator operation explicitly and commit its exact bytes
    before asking the Runtime to publish ready.
    """

    runner = (
        "import hashlib,json,os,subprocess,sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "import agent_memory_index as m;"
        "import agent_memory_generated_index_capability as cap;"
        "import agent_memory_closeout as co;"
        # Only the fixture bypasses the transition assertion: production
        # preflight intentionally treats the generated file as immutable and
        # validates it instead of mutating formal memory content.
        "m.assert_runtime_ready=lambda _command:{};"
        "c=m.connect();"
        "m.init_db(c);"
        "m.scan(c);"
        "c.commit();"
        "c.close();"
        "head=subprocess.run(['git','-C',str(m.GIT_ROOT),'rev-parse','HEAD'],check=True,capture_output=True,text=True).stdout.strip();"
        "target=m.VAULT_ROOT/'INDEX.md';"
        "projection=sorted((p.resolve().relative_to(m.VAULT_ROOT).as_posix(),hashlib.sha256(p.read_bytes()).hexdigest()) for p in m.VAULT_ROOT.rglob('*.md') if p.is_file() and p.resolve()!=target.resolve());"
        "full_hash=hashlib.sha256(json.dumps(projection,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest();"
        "binding={'transaction_id':'1'*32,'actor':'test','task_sha256':'2'*64,'vault_root_sha256':hashlib.sha256(str(m.VAULT_ROOT).encode()).hexdigest(),'git_head':head,'index_base_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'full_vault_inputs_sha256':full_hash,'lease_fences_sha256':'6'*64};"
        "co._register_generated_index_closeout_transaction(transaction_binding=binding);"
        "issued=cap.issue_generated_index_capability(m.CONFIG_ROOT,state_db=m.STATE_DB,transaction_binding=binding,issuer_pid=os.getpid());"
        "auth=cap.consume_generated_index_capability(m.CONFIG_ROOT,state_db=m.STATE_DB,capability_path=issued['path'],token=issued['token'],expected_transaction_binding=binding,expected_parent_pid=os.getpid());"
        "c=m.connect();"
        "r=m.sync_generated_index(c,consumed_capability=auth);"
        "c.commit();"
        "c.close();"
        "print(json.dumps(r,sort_keys=True))"
    )
    completed = subprocess.run(
        [
            str(managed_python(runtime)),
            "-I",
            "-S",
            "-c",
            runner,
            str(runtime / "scripts"),
        ],
        cwd=runtime,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    staged = subprocess.run(
        ["git", "-C", str(vault), "add", "--", "INDEX.md"],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if staged.returncode != 0:
        raise AssertionError(staged.stdout + staged.stderr)
    dirty = subprocess.run(
        ["git", "-C", str(vault), "diff", "--cached", "--quiet", "--", "INDEX.md"],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if dirty.returncode == 1:
        committed = subprocess.run(
            [
                "git",
                "-C",
                str(vault),
                "-c",
                "user.name=Runtime Test",
                "-c",
                "user.email=runtime-test@example.invalid",
                "commit",
                "-qm",
                "synchronize generated index fixture",
            ],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if committed.returncode != 0:
            raise AssertionError(committed.stdout + committed.stderr)
    elif dirty.returncode != 0:
        raise AssertionError(dirty.stdout + dirty.stderr)
    generated = json.loads(completed.stdout)
    closeout_commit = subprocess.run(
        ["git", "-C", str(vault), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    ).stdout.strip().lower()
    with sqlite3.connect(runtime / "state.sqlite") as conn:
        changed = conn.execute(
            "UPDATE generated_index_closeout_transactions "
            "SET status='consumed', consumed_at_epoch=1, closeout_git_commit=? "
            "WHERE transaction_id=? AND status='generated_bound' AND generated_sha256=?",
            (closeout_commit, "1" * 32, str(generated["sha256"])),
        ).rowcount
        if changed != 1:
            raise AssertionError("generated index fixture transaction did not finalize")


class RuntimeInstallTests(unittest.TestCase):
    @staticmethod
    def transaction_manifest() -> dict[str, object]:
        return {
            "bundle_sha256": "a" * 64,
            "template_files": {},
        }

    @staticmethod
    def write_semantic_config(root: Path, python: Path) -> None:
        config = root / "config" / "agent-memory.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            "[semantic_retrieval]\n"
            "enabled = true\n"
            'semantic_mode = "required"\n'
            f"python = {json.dumps(str(python))}\n"
            f"dependency_lock = {json.dumps(str(root / 'requirements-vector.lock'))}\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            config.chmod(0o600)

    def test_persistent_transaction_rolls_back_bytes_and_preserves_created_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            original = root / "scripts" / "memoryctl"
            original.parent.mkdir(parents=True)
            original.write_bytes(b"old-runtime\n")
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            runtime_installer._runtime_transaction_publish_bytes(
                transaction,
                Path("scripts/memoryctl"),
                b"new-runtime\n",
                mode=0o700,
            )
            created = root / "scripts" / "agent_memory_audit.py"
            runtime_installer._runtime_transaction_publish_bytes(
                transaction,
                Path("scripts/agent_memory_audit.py"),
                b"created-by-failed-install\n",
                mode=0o600,
            )
            venv = root / ".venv"
            venv.mkdir()
            runtime_installer._write_venv_transaction_marker(
                venv,
                str(transaction["transaction_id"]),
            )
            runtime_installer._append_runtime_journal(
                transaction,
                {"event": "venv_create_started", "path": str(venv)},
            )

            rollback = runtime_installer.rollback_runtime_transaction(
                transaction,
                reason_code="INJECTED_FAILURE",
            )
            self.assertEqual(original.read_bytes(), b"old-runtime\n")
            self.assertFalse(created.exists())
            self.assertTrue(any(Path(path).read_bytes() == b"created-by-failed-install\n" for path in rollback["preserved_created"]))
            self.assertFalse(venv.exists())
            self.assertTrue(Path(rollback["recovered_venv"]).is_dir())
            journal = Path(transaction["journal_path"]).read_text(encoding="utf-8")
            self.assertIn('"event": "rolled_back"', journal)

    def test_startup_recovery_is_idempotent_and_exact_cas_blocks_external_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            original = root / "scripts" / "memoryctl"
            original.parent.mkdir(parents=True)
            original.write_bytes(b"old\n")
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            runtime_installer._runtime_transaction_publish_bytes(
                transaction,
                Path("scripts/memoryctl"),
                b"new\n",
                mode=0o700,
            )
            recovered = runtime_installer.recover_incomplete_runtime_transactions(root)
            self.assertEqual(len(recovered), 1)
            self.assertEqual(original.read_bytes(), b"old\n")
            self.assertEqual(runtime_installer.recover_incomplete_runtime_transactions(root), [])

            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            runtime_installer._runtime_transaction_publish_bytes(
                transaction,
                Path("scripts/memoryctl"),
                b"new-again\n",
                mode=0o700,
            )
            original.write_bytes(b"external-drift\n")
            with self.assertRaisesRegex(
                runtime_installer.StateSecurityError,
                "manual recovery",
            ):
                runtime_installer.recover_incomplete_runtime_transactions(root)
            self.assertEqual(original.read_bytes(), b"external-drift\n")
            self.assertIn(
                '"event": "recovery_required"',
                Path(transaction["journal_path"]).read_text(encoding="utf-8"),
            )

    def test_rollback_prevalidates_all_targets_before_restoring_any_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            first = root / "scripts" / "agent_memory_audit.py"
            later = root / "scripts" / "memoryctl"
            first.parent.mkdir(parents=True)
            first.write_bytes(b"first-original\n")
            later.write_bytes(b"later-original\n")
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            runtime_installer._runtime_transaction_publish_bytes(
                transaction,
                Path("scripts/agent_memory_audit.py"),
                b"first-installed\n",
                mode=0o600,
            )
            runtime_installer._runtime_transaction_publish_bytes(
                transaction,
                Path("scripts/memoryctl"),
                b"later-installed\n",
                mode=0o700,
            )
            later.write_bytes(b"external-drift\n")

            with self.assertRaisesRegex(
                runtime_installer.StateSecurityError,
                "rollback CAS mismatch",
            ):
                runtime_installer.rollback_runtime_transaction(
                    transaction,
                    reason_code="INJECTED_FAILURE",
                )

            self.assertEqual(first.read_bytes(), b"first-installed\n")
            self.assertEqual(later.read_bytes(), b"external-drift\n")

    def test_publish_cas_is_bound_to_snapshot_not_a_late_unbacked_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            target = root / "scripts" / "memoryctl"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"snapshot-baseline\n")
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )

            # This edit occurs after the durable snapshot.  The installer must
            # not adopt it as an unbacked `before` value and then overwrite it.
            target.write_bytes(b"concurrent-local-change\n")
            with self.assertRaisesRegex(
                runtime_installer.StateSecurityError,
                "changed since backup",
            ):
                runtime_installer._runtime_transaction_publish_bytes(
                    transaction,
                    Path("scripts/memoryctl"),
                    b"new-runtime\n",
                    mode=0o700,
                )
            self.assertEqual(target.read_bytes(), b"concurrent-local-change\n")
            journal = Path(transaction["journal_path"]).read_text(encoding="utf-8")
            self.assertNotIn('"event": "target_intent"', journal)

    def test_semantic_dependencies_bootstrap_only_the_authenticated_managed_venv(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            python = managed_python(root)
            python.parent.mkdir(parents=True)
            python.write_bytes(b"managed-python-placeholder\n")
            untrusted = root / "backups" / "runtime-old" / "untrusted-venv" / "bin" / "python"
            untrusted.parent.mkdir(parents=True)
            untrusted.write_bytes(b"must-not-run\n")
            dependency_lock = root / "requirements-vector.lock"
            dependency_lock.write_text("example-semantic==1.2.3\n", encoding="utf-8")
            self.write_semantic_config(root, python)
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            missing = {
                "ok": False,
                "expected": 1,
                "missing": ["example-semantic"],
                "mismatched": [],
                "returncode": 2,
            }
            satisfied = {
                "ok": True,
                "expected": 1,
                "missing": [],
                "mismatched": [],
                "returncode": 0,
            }
            completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(
                    runtime_installer,
                    "semantic_dependency_state",
                    side_effect=[missing, satisfied],
                ),
                mock.patch.object(
                    runtime_installer.subprocess,
                    "run",
                    return_value=completed,
                ) as invoked,
            ):
                result = runtime_installer.install_semantic_dependencies(
                    root,
                    python,
                    transaction=transaction,
                )
            self.assertEqual(result["status"], "installed")
            command = invoked.call_args.args[0]
            self.assertEqual(command[0], str(python))
            self.assertNotIn(str(untrusted), command)
            self.assertEqual(command[-1], str(dependency_lock))
            child_env = invoked.call_args.kwargs["env"]
            self.assertEqual(child_env["PIP_REQUIRE_VIRTUALENV"], "1")
            journal = Path(transaction["journal_path"]).read_text(encoding="utf-8")
            self.assertIn('"event": "semantic_dependencies_install_started"', journal)
            self.assertIn('"event": "semantic_dependencies_install_completed"', journal)

    def test_semantic_dependency_install_failure_is_durable_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            python = managed_python(root)
            python.parent.mkdir(parents=True)
            python.write_bytes(b"managed-python-placeholder\n")
            (root / "requirements-vector.lock").write_text(
                "example-semantic==1.2.3\n",
                encoding="utf-8",
            )
            self.write_semantic_config(root, python)
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            missing = {
                "ok": False,
                "expected": 1,
                "missing": ["example-semantic"],
                "mismatched": [],
                "returncode": 2,
            }
            failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="failed")
            with (
                mock.patch.object(
                    runtime_installer,
                    "semantic_dependency_state",
                    return_value=missing,
                ),
                mock.patch.object(
                    runtime_installer.subprocess,
                    "run",
                    return_value=failed,
                ),
                self.assertRaisesRegex(RuntimeError, "semantic dependency installation failed"),
            ):
                runtime_installer.install_semantic_dependencies(
                    root,
                    python,
                    transaction=transaction,
                )
            journal = Path(transaction["journal_path"]).read_text(encoding="utf-8")
            self.assertIn('"event": "semantic_dependencies_install_failed"', journal)
            self.assertIn('"reason_code": "PIP_INSTALL_FAILED"', journal)

    def test_main_failure_returns_backup_journal_and_recovery_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            fake_python = root / ".venv" / "bin" / "python"
            output = io.StringIO()
            with (
                mock.patch.object(sys, "argv", [
                    "install_runtime.py",
                    "--config-root", str(root),
                    "--json",
                ]),
                mock.patch.object(
                    runtime_installer,
                    "ensure_managed_python",
                    return_value=(fake_python, {"schema_version": 1}, None),
                ),
                mock.patch.object(
                    runtime_installer,
                    "install",
                    side_effect=RuntimeError("INJECTED_INSTALL_FAILURE"),
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = runtime_installer.main()
            payload = json.loads(output.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertFalse(payload["ok"])
            self.assertTrue(Path(payload["backup"]).is_dir())
            self.assertTrue(Path(payload["transaction_journal"]).is_file())
            self.assertIn("recovered_venv", payload)
            self.assertIn("rollback", payload)

    def test_managed_python_subprocess_timeout_is_rolled_back_and_structured(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            output = io.StringIO()
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["install_runtime.py", "--config-root", str(root), "--json"],
                ),
                mock.patch.object(
                    runtime_installer,
                    "ensure_managed_python",
                    side_effect=subprocess.TimeoutExpired(
                        cmd=["python", "-m", "venv"],
                        timeout=180,
                    ),
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = runtime_installer.main()
            payload = json.loads(output.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"], "TimeoutExpired")
            self.assertTrue(Path(payload["backup"]).is_dir())
            self.assertTrue(Path(payload["transaction_journal"]).is_file())
            self.assertTrue(payload["rollback"]["event"] == "rolled_back")

    def test_pretransaction_failure_keeps_stable_recovery_evidence_shape(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            output = io.StringIO()
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["install_runtime.py", "--config-root", str(root), "--json"],
                ),
                mock.patch.object(
                    runtime_installer,
                    "recover_incomplete_runtime_transactions",
                    side_effect=runtime_installer.StateSecurityError(
                        "existing journal requires manual recovery"
                    ),
                ),
                contextlib.redirect_stdout(output),
            ):
                exit_code = runtime_installer.main()
            payload = json.loads(output.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertEqual(payload["backup"], "")
            self.assertEqual(payload["transaction_journal"], "")
            self.assertEqual(payload["recovered_untrusted_venv"], "")
            self.assertEqual(payload["recovered_venv"], "")
            self.assertEqual(payload["rollback"], {})

    def test_runtime_journal_seals_only_an_unterminated_crash_tail(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            journal = Path(transaction["journal_path"])
            with journal.open("ab") as handle:
                handle.write(b'{"event":"interrupted"')

            before_seal = runtime_installer._read_runtime_journal(journal)
            self.assertEqual([row["event"] for row in before_seal], ["prepared"])
            runtime_installer._append_runtime_journal(
                transaction,
                {"event": "venv_create_started", "path": str(root / ".venv")},
            )
            after_seal = runtime_installer._read_runtime_journal(journal)
            self.assertEqual(
                [row["event"] for row in after_seal],
                ["prepared", "journal_tail_recovered", "venv_create_started"],
            )
            recovered = runtime_installer.recover_incomplete_runtime_transactions(root)
            self.assertEqual(len(recovered), 1)
            self.assertEqual(runtime_installer.recover_incomplete_runtime_transactions(root), [])

            corrupt = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            corrupt_journal = Path(corrupt["journal_path"])
            with corrupt_journal.open("ab") as handle:
                handle.write(b"not-json\n")
            with self.assertRaisesRegex(
                runtime_installer.StateSecurityError,
                "journal is invalid",
            ):
                runtime_installer._read_runtime_journal(corrupt_journal)

    def test_verify_inventory_rejects_pending_or_recovery_required_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            pending = runtime_installer.runtime_transaction_health(root)
            self.assertFalse(pending["healthy"])
            self.assertEqual(pending["pending"], 1)

            runtime_installer._append_runtime_journal(
                transaction,
                {"event": "recovery_required", "reason_code": "INJECTED"},
            )
            recovery = runtime_installer.runtime_transaction_health(root)
            self.assertFalse(recovery["healthy"])
            self.assertEqual(recovery["pending"], 0)
            self.assertEqual(recovery["recovery_required"], 1)

    def test_orphan_runtime_backup_without_journal_is_never_reported_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            orphan = root / "backups" / "runtime-tx-orphaned-before-journal"
            orphan.mkdir(parents=True)
            (orphan / "snapshot.json").write_text("{}\n", encoding="utf-8")

            health = runtime_installer.runtime_transaction_health(root)

            self.assertFalse(health["healthy"])
            self.assertEqual(health["invalid"], 1)
            self.assertEqual(
                health["transactions"][0]["reason_code"],
                "RUNTIME_TRANSACTION_JOURNAL_MISSING_OR_UNSAFE",
            )
            with self.assertRaisesRegex(
                runtime_installer.StateSecurityError,
                "evidence is missing or unsafe",
            ):
                runtime_installer.recover_incomplete_runtime_transactions(root)
            self.assertTrue(orphan.is_dir())
            self.assertTrue((orphan / "snapshot.json").is_file())

    def test_legacy_prejournal_runtime_snapshot_is_not_reclassified_as_partial_install(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            legacy = root / "backups" / "runtime-20250101T000000Z-legacy"
            legacy.mkdir(parents=True)
            (legacy / "snapshot.json").write_text("{}\n", encoding="utf-8")

            health = runtime_installer.runtime_transaction_health(root)

            self.assertTrue(health["healthy"], health)
            self.assertEqual(health["transactions"], [])
            self.assertEqual(
                runtime_installer.recover_incomplete_runtime_transactions(root),
                [],
            )
            self.assertTrue(legacy.is_dir())

    def test_runtime_transaction_rejects_and_reports_events_after_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            runtime_installer._append_runtime_journal(
                transaction,
                {
                    "event": "completed",
                    "bundle_sha256": "a" * 64,
                    "backup_root": str(transaction["backup_root"]),
                },
            )
            with self.assertRaisesRegex(
                runtime_installer.StateSecurityError,
                "already terminal",
            ):
                runtime_installer._append_runtime_journal(
                    transaction,
                    {"event": "venv_create_started", "path": str(root / ".venv")},
                )

            journal = Path(transaction["journal_path"])
            with journal.open("ab") as handle:
                handle.write(
                    (
                        json.dumps({
                            "transaction_id": transaction["transaction_id"],
                            "recorded_at": runtime_installer.utc_now(),
                            "event": "venv_create_started",
                            "path": str(root / ".venv"),
                        }, sort_keys=True)
                        + "\n"
                    ).encode("utf-8")
                )
            health = runtime_installer.runtime_transaction_health(root)
            self.assertFalse(health["healthy"])
            self.assertEqual(health["invalid"], 1)
            self.assertEqual(
                health["transactions"][0]["reason_code"],
                "RUNTIME_TRANSACTION_JOURNAL_INVALID",
            )

    def test_transaction_journal_cannot_authorize_recovery_of_another_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            parent = Path(raw_root).resolve()
            first = parent / "first-runtime"
            second = parent / "second-runtime"
            second.mkdir()
            transaction = runtime_installer.begin_runtime_transaction(
                first,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            with self.assertRaisesRegex(
                runtime_installer.StateSecurityError,
                "another runtime root|outside private root",
            ):
                runtime_installer._transaction_from_journal(
                    Path(transaction["journal_path"]),
                    expected_config_root=second,
                )

    def test_corrupt_snapshot_mode_fails_closed_and_marks_recovery_required(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            target = root / "scripts" / "memoryctl"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"old-runtime\n")
            transaction = runtime_installer.begin_runtime_transaction(
                root,
                self.transaction_manifest(),  # type: ignore[arg-type]
            )
            snapshot_path = Path(transaction["backup_root"]) / "snapshot.json"
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            row = next(
                item for item in snapshot["files"]
                if item["path"] == "scripts/memoryctl"
            )
            row["mode"] = "invalid"
            snapshot_path.write_text(
                json.dumps(snapshot, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                runtime_installer.StateSecurityError,
                "manual recovery",
            ):
                runtime_installer.recover_incomplete_runtime_transactions(root)
            journal = Path(transaction["journal_path"]).read_text(encoding="utf-8")
            self.assertIn('"event": "recovery_required"', journal)
            self.assertEqual(target.read_bytes(), b"old-runtime\n")

    def test_installed_runtime_can_retrieve_revalidated_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            runtime = root / "runtime"
            vault = root / "vault"
            runtime_environment = isolated_runtime_env(root)
            memory = vault / "项目" / "example.md"
            memory.parent.mkdir(parents=True)
            memory.write_text(
                "---\n"
                "memory_type: project\n"
                "track: project\n"
                "app_id: ailu\n"
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
                env=runtime_environment,
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
                f"state_db = {json.dumps(str(runtime / 'state.sqlite'), ensure_ascii=False)}\n"
                f"config_root = {json.dumps(str(runtime), ensure_ascii=False)}\n"
                f"python = {json.dumps(str(managed_python(runtime)))}\n"
                "\n[write_gateway]\n"
                'mode = "enforce"\nwriter_protocol_version = 2\nstate_schema_required = 4\n'
                'canonical_actors = ["codex", "claude", "ailu"]\n'
                "path_fencing = true\nclaims_are_projection = true\nfull_vault = true\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                config.chmod(0o600)
            bootstrapped = subprocess.run(
                [
                    sys.executable,
                    str(runtime / "scripts" / "bootstrap.py"),
                    "--memory-root", str(vault),
                    "--config-root", str(runtime),
                    "--state-db", str(runtime / "state.sqlite"),
                    "--git-root", str(vault),
                ],
                cwd=runtime,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(bootstrapped.returncode, 0, bootstrapped.stdout + bootstrapped.stderr)
            committed = subprocess.run(
                [
                    "git", "-C", str(vault), "-c", "user.name=Runtime Test",
                    "-c", "user.email=runtime-test@example.invalid", "add", "--", "项目/example.md",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(committed.returncode, 0, committed.stdout + committed.stderr)
            committed = subprocess.run(
                [
                    "git", "-C", str(vault), "-c", "user.name=Runtime Test",
                    "-c", "user.email=runtime-test@example.invalid", "commit", "-qm", "add example memory",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(committed.returncode, 0, committed.stdout + committed.stderr)
            memoryctl = runtime / "scripts" / "memoryctl"
            initialized = subprocess.run(
                [sys.executable, "-I", "-S", str(memoryctl), "--actor", "migration", "migrate", "init", "--json"],
                cwd=runtime,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stdout + initialized.stderr)
            self.assertEqual(json.loads(initialized.stdout)["backup"]["status"], "not_applicable")
            audit_initialized = subprocess.run(
                [sys.executable, "-I", "-S", str(memoryctl), "--actor", "migration", "migrate", "audit-init", "--json"],
                cwd=runtime,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                audit_initialized.returncode,
                0,
                audit_initialized.stdout + audit_initialized.stderr,
            )
            synchronize_and_commit_generated_index(
                runtime,
                vault,
                environment=runtime_environment,
            )
            install_deferred_scheduler(
                runtime,
                environment=runtime_environment,
                backup_dir=root / "launchagent-backup",
            )
            migrated = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    str(memoryctl),
                    "--actor",
                    "migration",
                    "migrate",
                    "verify",
                    "--publish-ready",
                    "--no-host-hooks",
                    "--json",
                ],
                cwd=runtime,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(migrated.returncode, 0, migrated.stdout + migrated.stderr)
            self.assertTrue(json.loads(migrated.stdout)["runtime_transition"]["ready"])
            indexed = subprocess.run(
                [
                    str(memoryctl),
                    "--actor",
                    "migration",
                    "index",
                    "--init",
                    "--scan",
                ],
                cwd=runtime,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(indexed.returncode, 0, indexed.stdout + indexed.stderr)
            private_query = "runtimeprobe"
            retrieve_command = [
                sys.executable,
                "-I",
                "-S",
                str(memoryctl),
                "--actor",
                "ailu",
                "retrieve",
                "--json",
            ]
            self.assertNotIn(private_query, retrieve_command)
            retrieved = subprocess.run(
                retrieve_command,
                cwd=runtime,
                env=runtime_environment,
                input=json.dumps(
                    {
                        "schema_version": 2,
                        "query": private_query,
                        "app_id": "ailu",
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

    def test_preflight_bootstrap_attestation_reuses_new_venv_without_archiving_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            runtime_environment = isolated_runtime_env(root)
            first = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--json"],
                cwd=REPO_ROOT,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            marker_path = root / "config" / "runtime-transition.json"
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            self.assertEqual(marker["phase"], "state_migration_required")
            marker["phase"] = "preflight"
            marker["updated_at"] = "2026-08-24T00:00:00+00:00"
            marker_path.write_text(
                json.dumps(marker, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                marker_path.chmod(0o600)
            venv = root / ".venv"
            before_identity = (venv.stat().st_dev, venv.stat().st_ino)
            before_untrusted = sorted((root / "backups").glob("**/untrusted-venv-*"))

            second = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--json"],
                cwd=REPO_ROOT,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            payload = json.loads(second.stdout)
            self.assertEqual(payload["recovered_untrusted_venv"], "")
            self.assertEqual((venv.stat().st_dev, venv.stat().st_ino), before_identity)
            self.assertEqual(
                sorted((root / "backups").glob("**/untrusted-venv-*")),
                before_untrusted,
            )

    def test_preflight_venv_without_bootstrap_attestation_is_preserved_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            runtime_environment = isolated_runtime_env(root)
            first = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--json"],
                cwd=REPO_ROOT,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            marker_path = root / "config" / "runtime-transition.json"
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            marker["phase"] = "preflight"
            marker.pop("bootstrap_attestation", None)
            marker_path.write_text(
                json.dumps(marker, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                marker_path.chmod(0o600)
            original_venv = root / ".venv"
            original_identity = (original_venv.stat().st_dev, original_venv.stat().st_ino)

            second = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--json"],
                cwd=REPO_ROOT,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            payload = json.loads(second.stdout)
            preserved = Path(payload["recovered_untrusted_venv"])
            self.assertTrue(preserved.is_dir())
            self.assertEqual((preserved.stat().st_dev, preserved.stat().st_ino), original_identity)
            self.assertNotEqual(
                ((root / ".venv").stat().st_dev, (root / ".venv").stat().st_ino),
                original_identity,
            )

    def test_install_is_idempotent_and_preserves_local_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            runtime_environment = isolated_runtime_env(root)
            scripts = root / "scripts"
            scripts.mkdir(parents=True)
            local_adapter = scripts / "local_adapter.py"
            local_adapter.write_text("LOCAL = True\n", encoding="utf-8")

            first = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--json"],
                cwd=REPO_ROOT,
                env=runtime_environment,
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
            self.assertTrue((root / "scripts" / "agent_memory_migrate.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_content_migrate.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_state.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_lock.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_host_automation.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_generated_index_capability.py").is_file())
            self.assertTrue((root / "scripts" / "agent_memory_shadow.py").is_file())
            self.assertTrue((root / "scripts" / "install_audit_launchagent.py").is_file())
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
            manifest = json.loads(
                (root / "config" / "runtime-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(manifest["runtime_api_version"], 2)
            self.assertEqual(manifest["release_version"], "2.1.0")
            self.assertEqual(manifest["state_schema_required"], 4)
            self.assertEqual(manifest["writer_protocol_version"], 2)
            self.assertEqual(
                manifest["capabilities"]["write_gateway"],
                runtime_installer.WRITE_GATEWAY_CAPABILITIES,
            )
            self.assertEqual(manifest["canonical_actors"], ["codex", "claude", "ailu"])
            transition = json.loads(
                (root / "config" / "runtime-transition.json").read_text(encoding="utf-8")
            )
            self.assertEqual(transition["phase"], "state_migration_required")
            self.assertEqual(transition["bundle_sha256"], manifest["bundle_sha256"])

            verify = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--verify", "--json"],
                cwd=REPO_ROOT,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(verify.returncode, 2, verify.stdout + verify.stderr)
            self.assertFalse(json.loads(verify.stdout)["transition_ok"])

            vault = root / "vault"
            vault.mkdir()
            config = root / "config" / "agent-memory.toml"
            config.write_text(
                f"memory_root = {json.dumps(str(vault))}\n"
                f"git_root = {json.dumps(str(vault))}\n"
                f"state_db = {json.dumps(str(root / 'state.sqlite'))}\n"
                f"config_root = {json.dumps(str(root))}\n"
                f"python = {json.dumps(str(managed_python(root)))}\n"
                "\n[write_gateway]\n"
                'mode = "enforce"\nwriter_protocol_version = 2\nstate_schema_required = 4\n'
                'canonical_actors = ["codex", "claude", "ailu"]\n'
                "path_fencing = true\nclaims_are_projection = true\nfull_vault = true\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                config.chmod(0o600)
            bootstrapped = subprocess.run(
                [
                    sys.executable,
                    str(root / "scripts" / "bootstrap.py"),
                    "--memory-root", str(vault),
                    "--config-root", str(root),
                    "--state-db", str(root / "state.sqlite"),
                    "--git-root", str(vault),
                ],
                cwd=root,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(bootstrapped.returncode, 0, bootstrapped.stdout + bootstrapped.stderr)
            memoryctl = root / "scripts" / "memoryctl"
            migrated = subprocess.run(
                [
                    sys.executable, "-I", "-S", str(memoryctl),
                    "--actor", "migration", "migrate", "init", "--json",
                ],
                cwd=root,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(migrated.returncode, 0, migrated.stdout + migrated.stderr)
            audit_initialized = subprocess.run(
                [
                    sys.executable, "-I", "-S", str(memoryctl),
                    "--actor", "migration", "migrate", "audit-init", "--json",
                ],
                cwd=root,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                audit_initialized.returncode,
                0,
                audit_initialized.stdout + audit_initialized.stderr,
            )
            synchronize_and_commit_generated_index(
                root,
                vault,
                environment=runtime_environment,
            )
            install_deferred_scheduler(
                root,
                environment=runtime_environment,
                backup_dir=root / "launchagent-backup",
            )
            migrated = subprocess.run(
                [
                    sys.executable, "-I", "-S", str(memoryctl),
                    "--actor", "migration", "migrate", "verify",
                    "--publish-ready", "--no-host-hooks", "--json",
                ],
                cwd=root,
                env=runtime_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(migrated.returncode, 0, migrated.stdout + migrated.stderr)
            verify = subprocess.run(
                [sys.executable, str(INSTALLER), "--config-root", str(root), "--verify", "--json"],
                cwd=REPO_ROOT,
                env=runtime_environment,
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
                env=runtime_environment,
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
            install_payload = json.loads(installed.stdout)
            self.assertTrue(install_payload["state_migration_required"])
            transition = json.loads(
                (root / "config" / "runtime-transition.json").read_text(encoding="utf-8")
            )
            self.assertEqual(transition["phase"], "state_migration_required")
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
