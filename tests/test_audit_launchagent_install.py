from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_host_automation as automation
import install_audit_launchagent as installer


class AuditLaunchAgentInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "runtime"
        self.python = self.runtime / ".venv" / "bin" / "python"
        self.memoryctl = self.runtime / "scripts" / "memoryctl"
        self.python.parent.mkdir(parents=True)
        self.memoryctl.parent.mkdir(parents=True)
        self.python.write_text("python\n", encoding="utf-8")
        self.python.chmod(0o700)
        self.memoryctl.write_text("memoryctl\n", encoding="utf-8")
        self.memoryctl.chmod(0o700)
        self.spec = automation.LaunchAgentSpec(
            label="com.example.agent-memory-audit",
            plist_path=self.root / "Library" / "LaunchAgents" / "audit.plist",
            runtime_root=self.runtime,
            runtime_python=self.python,
            stdout_path=self.runtime / "logs" / "out.log",
            stderr_path=self.runtime / "logs" / "err.log",
            working_directory=self.root,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def loaded(*, runs: int = 1, healthy: bool = True) -> dict[str, object]:
        return {
            "loaded": True,
            "healthy": healthy,
            "runs": runs,
            "last_exit_code": 0 if healthy else 2,
            "arguments_exact": healthy,
            "program_exact": healthy,
            "state": "not running",
        }

    def legacy_bytes(self) -> bytes:
        payload = automation.launchagent_payload(self.spec)
        payload["ProgramArguments"] = [
            "/usr/bin/python3",
            str(self.runtime / "scripts" / "agent_memory_audit_autorun.py"),
            "--reason",
            "launchd",
            "--json",
        ]
        return __import__("plistlib").dumps(payload, sort_keys=False)

    def test_plan_is_read_only_and_classifies_legacy(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        before = self.legacy_bytes()
        self.spec.plist_path.write_bytes(before)
        with mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded(healthy=False)):
            plan = installer.plan_install(self.spec)
        self.assertTrue(plan["changed"])
        self.assertEqual(plan["classification"]["kind"], automation.LEGACY)
        self.assertEqual(self.spec.plist_path.read_bytes(), before)

    def test_unknown_launchctl_print_fails_before_backup_or_plist_mutation(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        before = self.legacy_bytes()
        self.spec.plist_path.write_bytes(before)
        backup_dir = self.root / "unknown-print-backup"
        unknown = automation.launchctl_health(
            print_returncode=127,
            print_stdout="",
            spec=self.spec,
        )
        self.assertEqual(unknown["load_state"], "unknown")
        self.assertFalse(unknown["query_ok"])
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=unknown,
            ),
        ):
            with self.assertRaisesRegex(
                installer.LaunchAgentError,
                "AUDIT_LAUNCHAGENT_PRINT_FAILED",
            ):
                installer.apply_install(
                    self.spec,
                    backup_dir=backup_dir,
                    defer_load=False,
                    kickstart_timeout=5,
                )
        self.assertEqual(self.spec.plist_path.read_bytes(), before)
        self.assertFalse(backup_dir.exists())

    def test_apply_replaces_legacy_with_backup_and_kickstart_evidence(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        before = self.legacy_bytes()
        self.spec.plist_path.write_bytes(before)
        backup_dir = self.root / "backup"
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded(healthy=False)),
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(installer, "_bootstrap"),
            mock.patch.object(installer, "_kickstart_and_wait", return_value=self.loaded(runs=2)),
        ):
            result = installer.apply_install(
                self.spec,
                backup_dir=backup_dir,
                defer_load=False,
                kickstart_timeout=5,
            )
        self.assertEqual(result["classification"]["kind"], automation.CANONICAL)
        self.assertTrue(result["loaded"]["healthy"])
        self.assertEqual(Path(result["backup_path"]).read_bytes(), before)
        self.assertTrue(Path(result["transaction_journal"]).is_file())

    def test_kickstart_waits_for_new_run_to_finish_not_previous_exit_zero(self) -> None:
        before = self.loaded(runs=1)
        still_running = {
            **self.loaded(runs=2),
            "state": "running",
            # launchctl can retain the prior successful exit while the new run
            # is still active.
            "last_exit_code": 0,
        }
        completed = self.loaded(runs=2)
        with (
            mock.patch.object(
                installer,
                "current_launchctl_health",
                side_effect=[before, still_running, completed],
            ) as health,
            mock.patch.object(
                installer,
                "run_launchctl",
                return_value={"returncode": 0, "stdout": "", "reason_code": ""},
            ),
            mock.patch.object(installer.time, "sleep"),
        ):
            result = installer._kickstart_and_wait(self.spec, 5)
        self.assertEqual(result["state"], "not running")
        self.assertEqual(health.call_count, 3)

    def test_canonical_apply_is_idempotent_but_keeps_transaction_evidence(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        canonical = automation.launchagent_bytes(self.spec)
        self.spec.plist_path.write_bytes(canonical)
        backup_dir = self.root / "unused-backup"
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded()),
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(installer, "_bootstrap"),
            mock.patch.object(installer, "_kickstart_and_wait", return_value=self.loaded(runs=2)),
        ):
            result = installer.apply_install(
                self.spec,
                backup_dir=backup_dir,
                defer_load=False,
                kickstart_timeout=5,
            )

        self.assertFalse(result["changed"])
        self.assertEqual(Path(result["backup_path"]).read_bytes(), canonical)
        self.assertTrue(Path(result["transaction_journal"]).is_file())
        self.assertEqual(self.spec.plist_path.read_bytes(), canonical)

    def test_late_loaded_health_failure_is_inside_rollback_boundary(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        before = self.legacy_bytes()
        self.spec.plist_path.write_bytes(before)
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded(healthy=False)),
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(installer, "_bootstrap"),
            mock.patch.object(installer, "_kickstart_and_wait", return_value=self.loaded(healthy=False)),
        ):
            with self.assertRaisesRegex(installer.LaunchAgentError, "VERIFY_FAILED"):
                installer.apply_install(
                    self.spec,
                    backup_dir=self.root / "late-health-backup",
                    defer_load=False,
                    kickstart_timeout=5,
                )
        self.assertEqual(self.spec.plist_path.read_bytes(), before)
        journal = (self.root / "late-health-backup" / "audit-launchagent-transaction.jsonl").read_text(
            encoding="utf-8"
        )
        self.assertIn('"event": "rolled_back"', journal)

    def test_deferred_finalize_failure_restores_original_bytes_and_loaded_state(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        before = self.legacy_bytes()
        self.spec.plist_path.write_bytes(before)
        backup_dir = self.root / "deferred-backup"
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded(healthy=False)),
        ):
            deferred = installer.apply_install(
                self.spec,
                backup_dir=backup_dir,
                defer_load=True,
                kickstart_timeout=5,
            )
        self.assertEqual(deferred["status"], "deferred")
        self.assertEqual(self.spec.plist_path.read_bytes(), automation.launchagent_bytes(self.spec))

        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded(healthy=False)),
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(installer, "_bootstrap") as bootstrap,
            mock.patch.object(
                installer,
                "_kickstart_and_wait",
                side_effect=installer.LaunchAgentError("INJECTED_FINALIZE_FAILURE", stage="kickstart"),
            ),
        ):
            with self.assertRaisesRegex(installer.LaunchAgentError, "INJECTED_FINALIZE_FAILURE"):
                installer.finalize_install(
                    self.spec,
                    Path(deferred["transaction_journal"]),
                    kickstart_timeout=5,
                )
        self.assertEqual(self.spec.plist_path.read_bytes(), before)
        self.assertGreaterEqual(bootstrap.call_count, 1)
        journal = Path(deferred["transaction_journal"]).read_text(encoding="utf-8")
        self.assertIn('"event": "deferred"', journal)
        self.assertIn('"event": "rolled_back"', journal)

    def test_deferred_finalize_is_idempotent_after_real_success_evidence(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        self.spec.plist_path.write_bytes(self.legacy_bytes())
        backup_dir = self.root / "finalize-success"
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded()),
        ):
            deferred = installer.apply_install(
                self.spec,
                backup_dir=backup_dir,
                defer_load=True,
                kickstart_timeout=5,
            )
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded(runs=2)),
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(installer, "_bootstrap"),
            mock.patch.object(installer, "_kickstart_and_wait", return_value=self.loaded(runs=2)),
        ):
            completed = installer.finalize_install(
                self.spec,
                Path(deferred["transaction_journal"]),
                kickstart_timeout=5,
            )
            replay = installer.finalize_install(
                self.spec,
                Path(deferred["transaction_journal"]),
                kickstart_timeout=5,
            )
        self.assertEqual(completed["status"], "applied")
        self.assertEqual(replay["status"], "already_completed")

    def test_deferred_transaction_blocks_new_apply_until_terminal(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        self.spec.plist_path.write_bytes(self.legacy_bytes())
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=self.loaded(healthy=False),
            ),
        ):
            deferred = installer.apply_install(
                self.spec,
                backup_dir=self.root / "fixed-pending-first",
                defer_load=True,
                kickstart_timeout=5,
            )
            health = installer.launchagent_transaction_health(self.runtime)
            self.assertFalse(health["healthy"])
            self.assertEqual(health["status"], "deferred")
            self.assertEqual(
                health["journal_path"],
                deferred["transaction_journal"],
            )
            with self.assertRaisesRegex(
                installer.LaunchAgentError,
                "TRANSACTION_DEFERRED",
            ):
                installer.apply_install(
                    self.spec,
                    backup_dir=self.root / "fixed-pending-second",
                    defer_load=True,
                    kickstart_timeout=5,
                )

            with (
                mock.patch.object(installer, "_bootout_if_loaded"),
                mock.patch.object(installer, "_bootstrap"),
                mock.patch.object(
                    installer,
                    "_kickstart_and_wait",
                    return_value=self.loaded(runs=2),
                ),
            ):
                installer.finalize_install(
                    self.spec,
                    Path(deferred["transaction_journal"]),
                    kickstart_timeout=5,
                )
        terminal = installer.launchagent_transaction_health(self.runtime)
        self.assertTrue(terminal["healthy"])
        self.assertEqual(terminal["status"], "terminal")

    def test_fixed_state_crash_tail_can_be_sealed_to_terminal(self) -> None:
        transaction_id = "a" * 32
        journal = self.root / "backup" / "audit-launchagent-transaction.jsonl"
        journal.parent.mkdir(parents=True)
        self.spec.plist_path.parent.mkdir(parents=True)
        canonical = automation.launchagent_bytes(self.spec)
        self.spec.plist_path.write_bytes(canonical)
        backup = installer.exclusive_backup(
            self.spec.plist_path,
            journal.parent,
            canonical,
            True,
        )
        installer.write_journal(
            journal,
            {
                "schema_version": 1,
                "event": "prepared",
                "transaction_id": transaction_id,
                "label": self.spec.label,
                "plist_path": str(self.spec.plist_path),
                "backup_path": str(backup),
                "backup_dir": str(journal.parent),
                "before_existed": True,
                "before_loaded": True,
                "before_sha256": installer.sha256_bytes(canonical),
                "after_sha256": installer.sha256_bytes(canonical),
                "changed": False,
            },
            create=True,
        )
        installer.write_journal(journal, {"event": "completed"})
        state = installer.launchagent_state_path(self.spec)
        installer.append_launchagent_state(
            self.spec,
            transaction_id=transaction_id,
            journal_path=journal,
            event="prepared",
        )
        with state.open("ab") as handle:
            handle.write(b'{"event":"interrupted"')
        installer.append_launchagent_state(
            self.spec,
            transaction_id=transaction_id,
            journal_path=journal,
            event="completed",
        )
        health = installer.launchagent_transaction_health(self.runtime)
        self.assertTrue(health["healthy"], health)
        self.assertEqual(health["status"], "terminal")

    def test_completed_finalize_can_be_compensated_when_later_acceptance_fails(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        before = self.legacy_bytes()
        self.spec.plist_path.write_bytes(before)
        not_loaded = {**self.loaded(healthy=False), "loaded": False}
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=not_loaded,
            ),
        ):
            deferred = installer.apply_install(
                self.spec,
                backup_dir=self.root / "post-finalize-compensation",
                defer_load=True,
                kickstart_timeout=5,
            )
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=self.loaded(runs=2),
            ),
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(installer, "_bootstrap"),
            mock.patch.object(
                installer,
                "_kickstart_and_wait",
                return_value=self.loaded(runs=2),
            ),
        ):
            completed = installer.finalize_install(
                self.spec,
                Path(deferred["transaction_journal"]),
                kickstart_timeout=5,
            )
        self.assertEqual(completed["status"], "applied")

        with (
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=not_loaded,
            ),
        ):
            rolled_back = installer.explicit_rollback(
                self.spec,
                Path(deferred["transaction_journal"]),
            )
        self.assertEqual(rolled_back["status"], "rolled_back")
        self.assertEqual(self.spec.plist_path.read_bytes(), before)
        journal = Path(deferred["transaction_journal"]).read_text(encoding="utf-8")
        self.assertIn('"event": "completed"', journal)
        self.assertIn('"event": "manual_rollback_completed"', journal)

    def test_finalize_refuses_journal_already_marked_recovery_required(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        self.spec.plist_path.write_bytes(self.legacy_bytes())
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=self.loaded(healthy=False),
            ),
        ):
            deferred = installer.apply_install(
                self.spec,
                backup_dir=self.root / "recovery-required",
                defer_load=True,
                kickstart_timeout=5,
            )
        journal = Path(deferred["transaction_journal"])
        installer.write_journal(
            journal,
            {"event": "recovery_required", "reason_code": "INJECTED"},
        )
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "_bootout_if_loaded") as bootout,
        ):
            with self.assertRaisesRegex(
                installer.LaunchAgentError,
                "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
            ):
                installer.finalize_install(
                    self.spec,
                    journal,
                    kickstart_timeout=5,
                )
        bootout.assert_not_called()

    def test_finalize_rejects_journal_rebound_to_another_backup_directory(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        self.spec.plist_path.write_bytes(self.legacy_bytes())
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=self.loaded(healthy=False),
            ),
        ):
            deferred = installer.apply_install(
                self.spec,
                backup_dir=self.root / "journal-boundary",
                defer_load=True,
                kickstart_timeout=5,
            )
        journal_path = Path(deferred["transaction_journal"])
        rows = [
            __import__("json").loads(line)
            for line in journal_path.read_text(encoding="utf-8").splitlines()
        ]
        rows[0]["backup_dir"] = str(self.root / "another-backup")
        journal_path.write_text(
            "".join(
                __import__("json").dumps(row, sort_keys=True) + "\n"
                for row in rows
            ),
            encoding="utf-8",
        )
        with mock.patch.object(installer.sys, "platform", "darwin"):
            with self.assertRaisesRegex(
                installer.LaunchAgentError,
                "JOURNAL_BOUNDARY_INVALID",
            ):
                installer.finalize_install(
                    self.spec,
                    journal_path,
                    kickstart_timeout=5,
                )
        self.assertEqual(
            self.spec.plist_path.read_bytes(),
            automation.launchagent_bytes(self.spec),
        )

    def test_journal_seals_only_an_unterminated_crash_tail(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        self.spec.plist_path.write_bytes(self.legacy_bytes())
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=self.loaded(healthy=False),
            ),
        ):
            deferred = installer.apply_install(
                self.spec,
                backup_dir=self.root / "crash-tail",
                defer_load=True,
                kickstart_timeout=5,
            )
        journal = Path(deferred["transaction_journal"])
        with journal.open("ab") as handle:
            handle.write(b'{"event":"interrupted"')

        _, before_seal = installer.read_journal(journal)
        self.assertNotIn("interrupted", [row.get("event") for row in before_seal])
        installer.write_journal(
            journal,
            {"event": "recovery_required", "reason_code": "POST_CRASH_PROBE"},
        )
        _, after_seal = installer.read_journal(journal)
        self.assertIn("journal_tail_recovered", [row.get("event") for row in after_seal])
        self.assertIn("recovery_required", [row.get("event") for row in after_seal])

        corrupt = self.root / "complete-corrupt.jsonl"
        corrupt.write_bytes(journal.read_bytes() + b"not-json\n")
        with self.assertRaisesRegex(
            installer.LaunchAgentError,
            "AUDIT_LAUNCHAGENT_JOURNAL_INVALID",
        ):
            installer.read_journal(corrupt)

    def test_failure_restores_existing_legacy_bytes(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        before = self.legacy_bytes()
        self.spec.plist_path.write_bytes(before)
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value=self.loaded(healthy=False)),
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(installer, "_bootstrap"),
            mock.patch.object(
                installer,
                "_kickstart_and_wait",
                side_effect=installer.LaunchAgentError("INJECTED_FAILURE", stage="kickstart"),
            ),
        ):
            with self.assertRaisesRegex(installer.LaunchAgentError, "INJECTED_FAILURE"):
                installer.apply_install(
                    self.spec,
                    backup_dir=self.root / "backup",
                    defer_load=False,
                    kickstart_timeout=5,
                )
        self.assertEqual(self.spec.plist_path.read_bytes(), before)

    def test_failed_fresh_install_preserves_created_plist_in_backup(self) -> None:
        backup_dir = self.root / "backup"
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer, "current_launchctl_health", return_value={**self.loaded(), "loaded": False}),
            mock.patch.object(installer, "_bootout_if_loaded"),
            mock.patch.object(installer, "_bootstrap"),
            mock.patch.object(
                installer,
                "_kickstart_and_wait",
                side_effect=installer.LaunchAgentError("INJECTED_FAILURE", stage="kickstart"),
            ),
        ):
            with self.assertRaisesRegex(installer.LaunchAgentError, "INJECTED_FAILURE"):
                installer.apply_install(
                    self.spec,
                    backup_dir=backup_dir,
                    defer_load=False,
                    kickstart_timeout=5,
                )
        self.assertFalse(self.spec.plist_path.exists())
        preserved = list(backup_dir.glob("created-*.preserved-*"))
        self.assertEqual(len(preserved), 1)
        self.assertEqual(preserved[0].read_bytes(), automation.launchagent_bytes(self.spec))

    def test_atomic_write_fails_closed_on_byte_cas_drift(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        self.spec.plist_path.write_bytes(b"external")
        with self.assertRaisesRegex(installer.LaunchAgentError, "CHANGED_BEFORE_REPLACE"):
            installer.atomic_write(
                self.spec.plist_path,
                b"desired",
                expected_before=b"planned",
                expected_existed=True,
            )

    def test_rollback_cas_drift_is_rejected_before_bootout(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        self.spec.plist_path.write_bytes(b"external-drift")
        with mock.patch.object(installer, "_bootout_if_loaded") as bootout:
            with self.assertRaisesRegex(
                installer.LaunchAgentError,
                "ROLLBACK_CAS_MISMATCH",
            ):
                installer.rollback_prepared(
                    spec=self.spec,
                    before=b"original",
                    before_existed=True,
                    before_loaded=True,
                    desired=automation.launchagent_bytes(self.spec),
                    backup_dir=self.root / "rollback-cas",
                )
        bootout.assert_not_called()
        self.assertEqual(self.spec.plist_path.read_bytes(), b"external-drift")

    def test_explicit_rollback_failure_appends_recovery_required(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        self.spec.plist_path.write_bytes(self.legacy_bytes())
        with (
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer,
                "current_launchctl_health",
                return_value=self.loaded(healthy=False),
            ),
        ):
            deferred = installer.apply_install(
                self.spec,
                backup_dir=self.root / "rollback-recovery-required",
                defer_load=True,
                kickstart_timeout=5,
            )
        self.spec.plist_path.write_bytes(b"external-drift")
        with self.assertRaisesRegex(
            installer.LaunchAgentError,
            "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
        ):
            installer.explicit_rollback(
                self.spec,
                Path(deferred["transaction_journal"]),
            )
        journal = Path(deferred["transaction_journal"]).read_text(encoding="utf-8")
        self.assertIn('"event": "recovery_required"', journal)
        self.assertEqual(self.spec.plist_path.read_bytes(), b"external-drift")

    def test_apply_refuses_a_second_scheduler_without_modifying_either_plist(self) -> None:
        self.spec.plist_path.parent.mkdir(parents=True)
        canonical = automation.launchagent_bytes(self.spec)
        self.spec.plist_path.write_bytes(canonical)
        duplicate = self.spec.plist_path.parent / "duplicate.plist"
        duplicate.write_bytes(canonical)
        with mock.patch.object(installer.sys, "platform", "darwin"):
            with self.assertRaisesRegex(installer.LaunchAgentError, "DUPLICATE_SCHEDULER"):
                installer.apply_install(
                    self.spec,
                    backup_dir=self.root / "backup",
                    defer_load=False,
                    kickstart_timeout=5,
                )
        self.assertEqual(self.spec.plist_path.read_bytes(), canonical)
        self.assertEqual(duplicate.read_bytes(), canonical)


if __name__ == "__main__":
    unittest.main()
