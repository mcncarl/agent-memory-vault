from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_content_migrate as content_migrate


def load_installer():
    path = SCRIPTS / "install-posix.py"
    loader = importlib.machinery.SourceFileLoader(
        "test_posix_launchagent_installer",
        str(path),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class PosixLaunchAgentPolicyTests(unittest.TestCase):
    @staticmethod
    def empty_attestation() -> dict[str, object]:
        legacy_binding = "a" * 64
        governance_fingerprint = "b" * 64
        combined = content_migrate.canonical_sha256({
            "schema_version": 1,
            "legacy_binding_sha256": legacy_binding,
            "governance_automatic_migration_fingerprint_sha256": governance_fingerprint,
        })
        content_debt = {
            "schema_version": 1,
            "legacy_scope_documents": 0,
            "safe_automatic_governance_documents": 0,
            "governance_metadata_automatic_documents": 0,
            "governance_risk_automatic_documents": 0,
            "governance_automatic_overlap_documents": 0,
            "governance_manual_review_documents": 0,
            "governance_unsafe_documents": 0,
            "temporal_failure_documents": 0,
            "legacy_binding_sha256": legacy_binding,
            "governance_binding_sha256": "c" * 64,
            "governance_automatic_migration_fingerprint_sha256": governance_fingerprint,
            "automatic_migration_fingerprint_sha256": combined,
            "reason_codes": [],
        }
        return {
            "content_migration_required": False,
            "legacy_scope_documents": 0,
            "safe_automatic_governance_documents": 0,
            "content_migration": content_debt,
        }

    def args(self, **overrides):
        values = {
            "host": [],
            "no_host_hooks": True,
            "config_root": "/private/runtime",
            "memory_root": "/private/vault",
            "git_root": "/private/vault",
            "state_db": "/private/runtime/state.sqlite",
            "python": "",
            "config_backup": "",
            "state_backup": "",
            "disposition_file": "",
            "hook_backup_dir": "",
            "launchagent_backup_dir": "/private/backups/launchagent-new",
            "user_id": "user",
            "agent_id": "shared",
            "app_id": "agent-memory",
        }
        values.update(overrides)
        return mock.Mock(**values)

    @staticmethod
    def paths() -> dict[str, Path]:
        return {
            "config_root": Path("/private/runtime"),
            "config": Path("/private/runtime/config/agent-memory.toml"),
            "state": Path("/private/runtime/state.sqlite"),
            "config_backup": Path(),
            "state_backup": Path(),
            "hook_backup_dir": Path(),
            "launchagent_backup_dir": Path("/private/backups/launchagent-new"),
            "disposition": Path(),
        }

    @staticmethod
    def discovered() -> dict[str, object]:
        return {
            "mode": "fresh",
            "config_exists": False,
            "state_exists": False,
            "configured": None,
            "environment": {},
            "vault": {"ok": True, "mutation": "bootstrap-on-apply"},
        }

    def test_run_json_binds_final_doctor_exit_and_envelope(self) -> None:
        module = load_installer()
        invalid_payloads = (
            (
                2,
                {"ok": True, "status": "warning", "summary": {"pass": 1, "warn": 1, "fail": 0}},
            ),
            (
                0,
                {"ok": False, "status": "error", "summary": {"pass": 1, "warn": 0, "fail": 1}},
            ),
            (
                2,
                {"ok": False, "status": "error", "summary": {"pass": True, "warn": 0, "fail": 1}},
            ),
        )
        for returncode, payload in invalid_payloads:
            completed = mock.Mock(
                returncode=returncode,
                stdout=json.dumps(payload),
            )
            with mock.patch.object(module.subprocess, "run", return_value=completed):
                with self.assertRaisesRegex(
                    module.PosixInstallError,
                    "PREFLIGHT_DOCTOR_PROCESS_CONTRACT_INVALID",
                ):
                    module.run_json(
                        ["python", "doctor"],
                        stage="final-doctor",
                        environment={},
                        require_ok=False,
                        allow_blocked=True,
                        doctor_process_contract=True,
                    )

    def test_darwin_plan_requires_launchagent_backup_even_without_host_hooks(self) -> None:
        module = load_installer()
        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module, "private_paths", return_value=self.paths()),
            mock.patch.object(module, "host_policy", return_value=([], ["--no-host-hooks"])),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation", return_value=self.discovered()),
            mock.patch.object(module, "run_json", return_value={"ok": True, "status": "planned"}) as run,
        ):
            result = module.plan(self.args())

        self.assertIn(
            "--launchagent-backup-dir NEW_PRIVATE_DIRECTORY",
            result["required_inputs"],
        )
        self.assertIn("audit_launchagent", result)
        self.assertIn(
            "audit-launchagent-plan",
            [call.kwargs["stage"] for call in run.call_args_list],
        )

    def test_plan_surfaces_fixable_unhealthy_scheduler_without_hiding_reason(self) -> None:
        module = load_installer()

        def child_result(*_args, **kwargs):
            if kwargs["stage"] == "audit-launchagent-plan":
                return {
                    "ok": False,
                    "status": "planned",
                    "classification": {
                        "kind": "legacy",
                        "reason_code": "AUDIT_LAUNCHAGENT_DIRECT_SCRIPT_LEGACY",
                    },
                }
            return {"ok": True, "status": "planned"}

        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module, "private_paths", return_value=self.paths()),
            mock.patch.object(module, "host_policy", return_value=([], ["--no-host-hooks"])),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation", return_value=self.discovered()),
            mock.patch.object(module, "run_json", side_effect=child_result),
        ):
            result = module.plan(self.args())

        self.assertTrue(result["ok"])
        self.assertFalse(result["audit_launchagent"]["ok"])
        self.assertEqual(
            result["audit_launchagent"]["classification"]["reason_code"],
            "AUDIT_LAUNCHAGENT_DIRECT_SCRIPT_LEGACY",
        )

    def test_darwin_apply_installs_scheduler_when_host_hooks_are_disabled(self) -> None:
        module = load_installer()
        configured = {
            "memory_root": Path("/private/vault"),
            "git_root": Path("/private/vault"),
            "state_db": Path("/private/runtime/state.sqlite"),
        }

        def child_result(*_args, **kwargs):
            if kwargs["stage"] == "publish-ready":
                return {
                    "ok": True,
                    "preflight_attestation": self.empty_attestation(),
                }
            if kwargs["stage"] == "audit-launchagent-deferred":
                return {
                    "ok": True,
                    "status": "deferred",
                    "transaction_journal": "/private/backups/launchagent-new/audit-launchagent-transaction.jsonl",
                }
            return {"ok": True, "stage": kwargs["stage"]}

        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module, "private_paths", return_value=self.paths()),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation", return_value=self.discovered()),
            mock.patch.object(module, "ensure_unused"),
            mock.patch.object(
                module,
                "prepare_private_backup_parents",
                return_value={"ok": True, "private_parents": []},
            ),
            mock.patch.object(module, "configured_paths", return_value=configured),
            mock.patch.object(module, "create_fresh_config"),
            mock.patch.object(module, "run_plain", return_value={"ok": True}),
            mock.patch.object(module, "run_json", side_effect=child_result) as run,
        ):
            result = module.apply(self.args())

        stages = [item["stage"] for item in result["stages"]]
        self.assertNotIn("host-hooks", stages)
        self.assertLess(stages.index("audit-launchagent-deferred"), stages.index("publish-ready"))
        self.assertLess(stages.index("publish-ready"), stages.index("audit-launchagent-kickstart"))
        self.assertLess(stages.index("audit-launchagent-kickstart"), stages.index("final-doctor"))
        launch_calls = [
            call.args[0]
            for call in run.call_args_list
            if call.kwargs["stage"] in {
                "audit-launchagent-deferred",
                "audit-launchagent-kickstart",
            }
        ]
        self.assertEqual(len(launch_calls), 2)
        deferred, finalized = launch_calls
        backup_index = deferred.index("--backup-dir") + 1
        self.assertEqual(deferred[backup_index], "/private/backups/launchagent-new")
        self.assertIn("--defer-load", deferred)
        self.assertIn("--finalize", finalized)
        journal_index = finalized.index("--journal") + 1
        self.assertEqual(
            finalized[journal_index],
            "/private/backups/launchagent-new/audit-launchagent-transaction.jsonl",
        )
        self.assertNotIn("--backup-dir", finalized)
        for call in run.call_args_list:
            if call.kwargs["stage"] in {
                "state-init",
                "audit-init",
                "generated-index-migrate",
                "publish-ready",
                "audit-launchagent-deferred",
                "audit-launchagent-kickstart",
                "final-doctor",
            }:
                self.assertEqual(call.args[0][0], "/private/runtime/.venv/bin/python")
                self.assertEqual(call.args[0][1:3], ["-I", "-S"])
        final_doctor_call = next(
            call
            for call in run.call_args_list
            if call.kwargs["stage"] == "final-doctor"
        )
        self.assertFalse(final_doctor_call.kwargs["require_ok"])
        self.assertTrue(final_doctor_call.kwargs["allow_blocked"])
        self.assertTrue(final_doctor_call.kwargs["doctor_process_contract"])
        self.assertTrue(callable(final_doctor_call.kwargs["payload_validator"]))

    def test_darwin_apply_rejects_missing_launchagent_backup_before_mutation(self) -> None:
        module = load_installer()
        args = self.args(launchagent_backup_dir="")
        paths = self.paths()
        paths["launchagent_backup_dir"] = Path()
        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module, "private_paths", return_value=paths),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation", return_value=self.discovered()),
            mock.patch.object(module, "run_json") as run,
            mock.patch.object(module, "run_plain") as plain,
        ):
            with self.assertRaisesRegex(
                module.PosixInstallError,
                "LAUNCHAGENT_BACKUP_DIR_REQUIRED",
            ):
                module.apply(args)
        run.assert_not_called()
        plain.assert_not_called()

    def test_runtime_bundle_must_match_outer_install_source_binding(self) -> None:
        module = load_installer()
        expected_bundle = "a" * 64

        def child_result(*_args, **kwargs):
            if kwargs["stage"] == "generated-index-plan":
                return {"ok": True, "status": "bootstrap_pending", "blocking": False}
            if kwargs["stage"] == "runtime-install":
                return {"ok": True, "bundle_sha256": "b" * 64}
            raise AssertionError(kwargs["stage"])

        context = {
            "transaction_id": "1" * 32,
            "input_sha256": "2" * 64,
            "input_projection": {"runtime_bundle_sha256": expected_bundle},
        }
        with (
            mock.patch.object(module.sys, "platform", "linux"),
            mock.patch.object(module, "_ACTIVE_INSTALL_TRANSACTION", context),
            mock.patch.object(module, "private_paths", return_value=self.paths()),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation_for_apply", return_value=self.discovered()),
            mock.patch.object(
                module,
                "_transaction_stage_started",
                return_value={"ok": True, "private_parents": []},
            ),
            mock.patch.object(module, "run_json", side_effect=child_result),
            mock.patch.object(module, "configured_paths") as configured,
            mock.patch.object(module, "run_plain") as plain,
        ):
            with self.assertRaises(module.PosixInstallError) as raised:
                module.apply(self.args(launchagent_backup_dir=""))

        self.assertEqual(raised.exception.reason_code, "INSTALL_RUNTIME_SOURCE_MISMATCH")
        self.assertEqual(raised.exception.stage, "runtime-install")
        self.assertEqual(raised.exception.evidence["expected_bundle_sha256"], expected_bundle)
        configured.assert_not_called()
        plain.assert_not_called()

    def test_publish_failure_compensates_deferred_launchagent_from_its_journal(self) -> None:
        module = load_installer()
        configured = {
            "memory_root": Path("/private/vault"),
            "git_root": Path("/private/vault"),
            "state_db": Path("/private/runtime/state.sqlite"),
        }
        journal = "/private/backups/launchagent-new/audit-launchagent-transaction.jsonl"

        def child_result(*_args, **kwargs):
            stage = kwargs["stage"]
            if stage == "audit-launchagent-deferred":
                return {"ok": True, "status": "deferred", "transaction_journal": journal}
            if stage == "publish-ready":
                raise module.PosixInstallError("PREFLIGHT_DOCTOR_FAILED", stage)
            if stage == "audit-launchagent-rollback":
                return {"ok": True, "status": "rolled_back", "transaction_journal": journal}
            return {"ok": True, "stage": stage}

        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module, "private_paths", return_value=self.paths()),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation", return_value=self.discovered()),
            mock.patch.object(module, "ensure_unused"),
            mock.patch.object(
                module,
                "prepare_private_backup_parents",
                return_value={"ok": True, "private_parents": []},
            ),
            mock.patch.object(module, "configured_paths", return_value=configured),
            mock.patch.object(module, "create_fresh_config"),
            mock.patch.object(module, "run_plain", return_value={"ok": True}),
            mock.patch.object(module, "run_json", side_effect=child_result) as run,
        ):
            with self.assertRaises(module.PosixInstallError) as raised:
                module.apply(self.args())

        self.assertEqual(raised.exception.reason_code, "PREFLIGHT_DOCTOR_FAILED")
        self.assertTrue(raised.exception.evidence["launchagent_compensation"]["ok"])
        stages = [call.kwargs["stage"] for call in run.call_args_list]
        self.assertLess(stages.index("audit-launchagent-deferred"), stages.index("publish-ready"))
        self.assertEqual(stages[-1], "audit-launchagent-rollback")
        rollback_command = run.call_args_list[-1].args[0]
        self.assertIn("--rollback", rollback_command)
        self.assertEqual(
            rollback_command[rollback_command.index("--journal") + 1],
            journal,
        )

    def test_final_doctor_failure_rolls_back_even_after_successful_finalize(self) -> None:
        module = load_installer()
        configured = {
            "memory_root": Path("/private/vault"),
            "git_root": Path("/private/vault"),
            "state_db": Path("/private/runtime/state.sqlite"),
        }
        journal = "/private/backups/launchagent-new/audit-launchagent-transaction.jsonl"

        def child_result(*_args, **kwargs):
            stage = kwargs["stage"]
            if stage == "audit-launchagent-deferred":
                return {"ok": True, "status": "deferred", "transaction_journal": journal}
            if stage == "publish-ready":
                return {
                    "ok": True,
                    "preflight_attestation": self.empty_attestation(),
                }
            if stage == "final-doctor":
                raise module.PosixInstallError("DOCTOR_FAILED", stage)
            if stage == "audit-launchagent-rollback":
                return {"ok": True, "status": "rolled_back", "transaction_journal": journal}
            return {"ok": True, "stage": stage}

        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module, "private_paths", return_value=self.paths()),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation", return_value=self.discovered()),
            mock.patch.object(module, "ensure_unused"),
            mock.patch.object(
                module,
                "prepare_private_backup_parents",
                return_value={"ok": True, "private_parents": []},
            ),
            mock.patch.object(module, "configured_paths", return_value=configured),
            mock.patch.object(module, "create_fresh_config"),
            mock.patch.object(module, "run_plain", return_value={"ok": True}),
            mock.patch.object(module, "run_json", side_effect=child_result) as run,
        ):
            with self.assertRaises(module.PosixInstallError) as raised:
                module.apply(self.args())

        self.assertEqual(raised.exception.reason_code, "DOCTOR_FAILED")
        stages = [call.kwargs["stage"] for call in run.call_args_list]
        self.assertLess(stages.index("audit-launchagent-kickstart"), stages.index("final-doctor"))
        self.assertEqual(stages[-1], "audit-launchagent-rollback")

    def test_failed_compensation_surfaces_recovery_journal_evidence(self) -> None:
        module = load_installer()
        configured = {
            "memory_root": Path("/private/vault"),
            "git_root": Path("/private/vault"),
            "state_db": Path("/private/runtime/state.sqlite"),
        }
        journal = "/private/backups/launchagent-new/audit-launchagent-transaction.jsonl"

        def child_result(*_args, **kwargs):
            stage = kwargs["stage"]
            if stage == "audit-launchagent-deferred":
                return {"ok": True, "status": "deferred", "transaction_journal": journal}
            if stage == "publish-ready":
                raise module.PosixInstallError("PUBLISH_FAILED", stage)
            if stage == "audit-launchagent-rollback":
                raise module.PosixInstallError("ROLLBACK_CAS_MISMATCH", stage)
            return {"ok": True, "stage": stage}

        with (
            mock.patch.object(module.sys, "platform", "darwin"),
            mock.patch.object(module, "private_paths", return_value=self.paths()),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation", return_value=self.discovered()),
            mock.patch.object(module, "ensure_unused"),
            mock.patch.object(
                module,
                "prepare_private_backup_parents",
                return_value={"ok": True, "private_parents": []},
            ),
            mock.patch.object(module, "configured_paths", return_value=configured),
            mock.patch.object(module, "create_fresh_config"),
            mock.patch.object(module, "run_plain", return_value={"ok": True}),
            mock.patch.object(module, "run_json", side_effect=child_result),
        ):
            with self.assertRaises(module.PosixInstallError) as raised:
                module.apply(self.args())

        self.assertEqual(
            raised.exception.reason_code,
            "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
        )
        self.assertEqual(raised.exception.evidence["transaction_journal"], journal)
        self.assertEqual(
            raised.exception.evidence["launchagent_compensation"]["reason_code"],
            "ROLLBACK_CAS_MISMATCH",
        )

    def test_non_darwin_keeps_scheduler_not_applicable(self) -> None:
        module = load_installer()
        with (
            mock.patch.object(module.sys, "platform", "linux"),
            mock.patch.object(module, "private_paths", return_value=self.paths()),
            mock.patch.object(module, "host_policy", return_value=([], ["--no-host-hooks"])),
            mock.patch.object(module, "select_supported_python", return_value=Path("/opt/python3.12")),
            mock.patch.object(module, "discover_installation", return_value=self.discovered()),
            mock.patch.object(module, "run_json", return_value={"ok": True, "status": "planned"}),
        ):
            result = module.plan(self.args(launchagent_backup_dir=""))
        self.assertNotIn("audit_launchagent", result)
        self.assertNotIn(
            "--launchagent-backup-dir NEW_PRIVATE_DIRECTORY",
            result["required_inputs"],
        )

class PosixOrchestrationJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_installer()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def args(self, **overrides) -> Namespace:
        values = {
            "host": [],
            "no_host_hooks": True,
            "config_root": str(self.root / "runtime"),
            "memory_root": str(self.root / "vault"),
            "git_root": str(self.root / "vault"),
            "state_db": str(self.root / "runtime" / "state.sqlite"),
            "python": "",
            "config_backup": "",
            "state_backup": "",
            "audit_backup": "",
            "disposition_file": "",
            "hook_backup_dir": "",
            "launchagent_backup_dir": "",
            "user_id": "user",
            "agent_id": "shared",
            "app_id": "agent-memory",
            "lock_timeout": 0.0,
            "supersede_interrupted": "",
        }
        values.update(overrides)
        return Namespace(**values)

    def journal(self, args: Namespace) -> Path:
        return self.module._install_journal_path(
            self.module.private_paths(args)["config_root"]
        )

    def test_managed_backup_batch_and_children_are_created_private(self) -> None:
        batch = self.root / "runtime" / "backups" / "install-unique"
        args = self.args(
            config_backup=str(batch / "config" / "agent-memory.toml"),
            state_backup=str(batch / "state" / "state.sqlite"),
            audit_backup=str(batch / "audit" / "audit.sqlite"),
            hook_backup_dir=str(batch / "hooks"),
            launchagent_backup_dir=str(batch / "launchagent"),
        )

        result = self.module.prepare_private_backup_parents(
            args,
            self.module.private_paths(args),
        )

        self.assertTrue(result["ok"])
        for directory in (
            self.root / "runtime" / "backups",
            batch,
            batch / "config",
            batch / "state",
            batch / "audit",
        ):
            self.assertTrue(directory.is_dir())
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertFalse((batch / "hooks").exists())
        self.assertFalse((batch / "launchagent").exists())

    @unittest.skipIf(sys.platform == "win32", "POSIX mode policy")
    def test_external_backup_parent_must_already_be_private(self) -> None:
        external = self.root / "shared"
        external.mkdir(mode=0o755)
        args = self.args(state_backup=str(external / "state.sqlite"))

        with self.assertRaises(self.module.PosixInstallError) as raised:
            self.module.prepare_private_backup_parents(
                args,
                self.module.private_paths(args),
            )

        self.assertEqual(raised.exception.reason_code, "BACKUP_PARENT_NOT_PRIVATE")
        self.assertEqual(external.stat().st_mode & 0o777, 0o755)

    def test_backup_targets_cannot_overlap_before_any_parent_is_created(self) -> None:
        batch = self.root / "runtime" / "backups" / "install-overlap"
        args = self.args(
            config_backup=str(batch / "hooks" / "config.toml"),
            hook_backup_dir=str(batch / "hooks"),
        )

        with self.assertRaises(self.module.PosixInstallError) as raised:
            self.module.prepare_private_backup_parents(
                args,
                self.module.private_paths(args),
            )

        self.assertEqual(raised.exception.reason_code, "BACKUP_TARGETS_OVERLAP")
        self.assertFalse(batch.exists())

    @unittest.skipIf(sys.platform == "win32", "POSIX symlink policy")
    def test_external_backup_rejects_symlink_ancestor(self) -> None:
        real = self.root / "real"
        real.mkdir(mode=0o700)
        batch = real / "batch"
        batch.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        args = self.args(state_backup=str(link / "batch" / "state.sqlite"))

        with self.assertRaises(self.module.PosixInstallError) as raised:
            self.module.prepare_private_backup_parents(
                args,
                self.module.private_paths(args),
            )

        self.assertEqual(raised.exception.reason_code, "BACKUP_PARENT_SYMLINK")

    def test_runtime_local_backup_must_stay_under_managed_backups(self) -> None:
        unsafe = self.root / "runtime" / "scripts"
        args = self.args(hook_backup_dir=str(unsafe))

        with self.assertRaises(self.module.PosixInstallError) as raised:
            self.module.prepare_private_backup_parents(
                args,
                self.module.private_paths(args),
            )

        self.assertEqual(
            raised.exception.reason_code,
            "BACKUP_TARGET_OUTSIDE_MANAGED_BACKUPS",
        )
        self.assertFalse(unsafe.exists())

    @unittest.skipIf(sys.platform == "win32", "POSIX mode policy")
    def test_completed_backup_receipt_is_rechecked_before_stage_skip(self) -> None:
        batch = self.root / "runtime" / "backups" / "receipt"
        batch.mkdir(mode=0o700, parents=True)
        backup = batch / "state.sqlite"
        backup.write_bytes(b"trusted-backup")
        backup.chmod(0o600)
        context = {
            "input_projection": {"state_backup": str(backup)},
            "resuming": True,
            "started_stages": {"state-apply"},
            "completed_results": {},
        }
        with mock.patch.object(self.module, "_ACTIVE_INSTALL_TRANSACTION", context):
            receipt = self.module._capture_stage_backup_receipt(
                "state-apply",
                {"ok": True, "backup": {"path": str(backup)}},
            )
        context["completed_results"] = {
            "state-apply": {"ok": True, "backup_receipt": receipt}
        }

        with mock.patch.object(self.module, "_ACTIVE_INSTALL_TRANSACTION", context):
            resumed = self.module._transaction_stage_started("state-apply")
        self.assertTrue(resumed["ok"])

        backup.write_bytes(b"replaced-backup")
        backup.chmod(0o600)
        with mock.patch.object(self.module, "_ACTIVE_INSTALL_TRANSACTION", context), self.assertRaises(
            self.module.PosixInstallError
        ) as raised:
            self.module._transaction_stage_started("state-apply")
        self.assertEqual(
            raised.exception.reason_code,
            "INSTALL_BACKUP_RECEIPT_MISMATCH",
        )

    @unittest.skipIf(sys.platform == "win32", "POSIX mode policy")
    def test_launchagent_receipt_allows_bound_journal_lifecycle_append(self) -> None:
        backup_dir = self.root / "runtime" / "backups" / "launch-receipt"
        backup_dir.mkdir(mode=0o700, parents=True)
        backup = backup_dir / "plist.before-v2"
        backup.write_bytes(b"plist-before")
        backup.chmod(0o600)
        journal = backup_dir / "audit-launchagent-transaction.jsonl"
        journal.write_text('{"event":"prepared"}\n', encoding="utf-8")
        journal.chmod(0o600)
        transaction_id = "b" * 32
        context = {
            "input_projection": {
                "config_root": str(self.root / "runtime"),
                "launchagent_backup_dir": str(backup_dir),
            },
            "completed_results": {},
        }
        deferred = {
            "transaction_id": transaction_id,
            "journal_path": str(journal),
            "status": "deferred",
            "child_status": "deferred",
            "recovery_required_seen": False,
        }
        with mock.patch.object(self.module, "_ACTIVE_INSTALL_TRANSACTION", context), mock.patch.object(
            self.module,
            "launchagent_transaction_health",
            return_value=deferred,
        ):
            receipt = self.module._capture_stage_backup_receipt(
                "audit-launchagent-deferred",
                {
                    "ok": True,
                    "backup_path": str(backup),
                    "transaction_journal": str(journal),
                },
            )

        journal.write_text(
            '{"event":"prepared"}\n{"event":"completed"}\n',
            encoding="utf-8",
        )
        journal.chmod(0o600)
        terminal = {
            **deferred,
            "status": "terminal",
            "child_status": "completed",
        }
        result = {"ok": True, "backup_receipt": receipt}
        with mock.patch.object(self.module, "_ACTIVE_INSTALL_TRANSACTION", context), mock.patch.object(
            self.module,
            "launchagent_transaction_health",
            return_value=terminal,
        ):
            self.module._verify_stage_backup_receipt(
                "audit-launchagent-deferred",
                result,
            )

    @unittest.skipUnless(sys.platform == "darwin", "macOS LaunchAgent policy")
    def test_supersede_accepts_exact_rolled_back_launchagent_receipt(self) -> None:
        backup_dir = self.root / "runtime" / "backups" / "launch-rollback"
        backup_dir.mkdir(mode=0o700, parents=True)
        backup = backup_dir / "plist.before-v2"
        backup.write_bytes(b"plist-before")
        backup.chmod(0o600)
        journal = backup_dir / "audit-launchagent-transaction.jsonl"
        journal.write_text('{"event":"prepared"}\n', encoding="utf-8")
        journal.chmod(0o600)
        child_transaction_id = "c" * 32
        args = self.args(launchagent_backup_dir=str(backup_dir))
        projection = self.module._install_input_projection(
            args,
            self.module.private_paths(args),
        )
        context = {"input_projection": projection, "completed_results": {}}
        deferred = {
            "transaction_id": child_transaction_id,
            "journal_path": str(journal),
            "status": "deferred",
            "child_status": "deferred",
            "recovery_required_seen": False,
        }
        with mock.patch.object(self.module, "_ACTIVE_INSTALL_TRANSACTION", context), mock.patch.object(
            self.module,
            "launchagent_transaction_health",
            return_value=deferred,
        ):
            receipt = self.module._capture_stage_backup_receipt(
                "audit-launchagent-deferred",
                {
                    "ok": True,
                    "backup_path": str(backup),
                    "transaction_journal": str(journal),
                },
            )
        outer_transaction_id = "d" * 32
        fingerprint = self.module._install_input_sha256(projection)
        tail = [
            {
                "event": "prepared",
                "transaction_id": outer_transaction_id,
                "input_sha256": fingerprint,
                "input_projection": projection,
            },
            {
                "event": "stage_started",
                "transaction_id": outer_transaction_id,
                "input_sha256": fingerprint,
                "stage": "runtime-install",
            },
            {
                "event": "stage_started",
                "transaction_id": outer_transaction_id,
                "input_sha256": fingerprint,
                "stage": "audit-launchagent-deferred",
            },
            {
                "event": "stage_completed",
                "transaction_id": outer_transaction_id,
                "input_sha256": fingerprint,
                "stage": "audit-launchagent-deferred",
                "result": {"ok": True, "backup_receipt": receipt},
            },
            {
                "event": "interrupted",
                "transaction_id": outer_transaction_id,
                "input_sha256": fingerprint,
                "stage": "publish-ready",
                "reason_code": "INJECTED",
            },
        ]
        rolled_back = {
            **deferred,
            "healthy": True,
            "status": "terminal",
            "child_status": "rolled_back",
            "journal_events_sha256": "e" * 64,
        }
        runtime_health = {
            "healthy": True,
            "bundle_sha256": projection["runtime_bundle_sha256"],
            "transition_phase": "preflight",
            "manifest_sha256": "1" * 64,
            "transition_sha256": "2" * 64,
            "install_id": "3" * 64,
            "runtime_anchor_sha256": "4" * 64,
            "runtime_transactions_sha256": "5" * 64,
        }
        with mock.patch.object(
            self.module,
            "launchagent_transaction_health",
            return_value=rolled_back,
        ), mock.patch.object(
            self.module.runtime_installer,
            "attest_installed_runtime_static",
            return_value=runtime_health,
        ):
            evidence = self.module._prove_interrupted_transaction_supersedable(
                tail=tail,
                config_root=self.module.private_paths(args)["config_root"],
            )

        self.assertTrue(evidence["launchagent_stage_started"])
        self.assertEqual(evidence["launchagent_child_status"], "rolled_back")

    @unittest.skipIf(sys.platform == "win32", "POSIX mode policy")
    def test_resume_revalidates_external_backup_parent_permissions(self) -> None:
        external = self.root / "external"
        external.mkdir(mode=0o700)
        target = external / "hooks"
        args = self.args(hook_backup_dir=str(target))
        context = {
            "resuming": True,
            "started_stages": {"host-hooks"},
        }

        with mock.patch.object(self.module, "_ACTIVE_INSTALL_TRANSACTION", context):
            self.module.prepare_private_backup_parents(
                args,
                self.module.private_paths(args),
            )
            external.chmod(0o755)
            with self.assertRaises(self.module.PosixInstallError) as raised:
                self.module.prepare_private_backup_parents(
                    args,
                    self.module.private_paths(args),
                )

        self.assertEqual(raised.exception.reason_code, "BACKUP_PARENT_NOT_PRIVATE")
        self.assertEqual(external.stat().st_mode & 0o777, 0o755)

    def test_resume_rejects_started_only_existing_backup_target(self) -> None:
        external = self.root / "external-unproven"
        external.mkdir(mode=0o700)
        target = external / "hooks"
        target.mkdir(mode=0o700)
        args = self.args(hook_backup_dir=str(target))
        context = {
            "resuming": True,
            "started_stages": {"host-hooks"},
            "completed_results": {},
        }

        with mock.patch.object(self.module, "_ACTIVE_INSTALL_TRANSACTION", context), self.assertRaises(
            self.module.PosixInstallError
        ) as raised:
            self.module.prepare_private_backup_parents(
                args,
                self.module.private_paths(args),
            )

        self.assertEqual(raised.exception.reason_code, "INSTALL_BACKUP_STAGE_UNPROVEN")

    def test_orchestration_health_requires_exact_binding_for_active_install(self) -> None:
        config_root = self.root / "runtime-health"
        journal = self.module._install_journal_path(config_root)
        transaction_id = "a" * 32
        input_projection: dict[str, object] = {}
        input_sha256 = self.module._install_input_sha256(input_projection)
        self.module._append_install_event(
            journal,
            {
                "event": "prepared",
                "transaction_id": transaction_id,
                "input_sha256": input_sha256,
                "input_projection": input_projection,
            },
        )

        open_health = self.module.install_orchestration_health(config_root)
        exact = self.module.install_orchestration_health(
            config_root,
            active_transaction_id=transaction_id,
            active_input_sha256=input_sha256,
        )
        wrong = self.module.install_orchestration_health(
            config_root,
            active_transaction_id="b" * 32,
            active_input_sha256=input_sha256,
        )

        self.assertFalse(open_health["healthy"])
        self.assertEqual(open_health["status"], "open")
        self.assertTrue(exact["healthy"])
        self.assertEqual(exact["status"], "active")
        self.assertFalse(wrong["healthy"])

        self.module._append_install_event(
            journal,
            {
                "event": "completed",
                "transaction_id": transaction_id,
                "input_sha256": input_sha256,
            },
        )
        terminal_with_binding = self.module.install_orchestration_health(
            config_root,
            active_transaction_id=transaction_id,
            active_input_sha256=input_sha256,
        )
        self.assertFalse(terminal_with_binding["healthy"])
        self.assertEqual(
            terminal_with_binding["reason_code"],
            "INSTALL_ACTIVE_BINDING_MISMATCH",
        )

    def test_orchestration_health_rejects_binding_when_journal_is_missing(self) -> None:
        health = self.module.install_orchestration_health(
            self.root / "missing-runtime",
            active_transaction_id="a" * 32,
            active_input_sha256="b" * 64,
        )
        self.assertFalse(health["healthy"])
        self.assertEqual(health["reason_code"], "INSTALL_ACTIVE_BINDING_NOT_FOUND")

    def test_generated_index_source_plan_runs_under_isolated_python(self) -> None:
        vault = self.root / "vault"
        vault.mkdir()
        (vault / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")
        (vault / "INDEX.md").write_text(
            "<!-- agent-memory-generated-index:v1 -->\n# Generated Index\n",
            encoding="utf-8",
        )
        for command in (
            ["git", "init", "-q"],
            ["git", "config", "user.name", "POSIX Plan Test"],
            ["git", "config", "user.email", "plan@example.invalid"],
            ["git", "add", "AGENTS.md", "INDEX.md"],
            ["git", "commit", "-qm", "baseline"],
        ):
            self.module.subprocess.run(
                command,
                cwd=vault,
                check=True,
                capture_output=True,
            )
        args = self.args(memory_root=str(vault), git_root=str(vault))
        environment = dict(self.module.os.environ)
        environment.update({
            "AGENT_MEMORY_CONFIG_ROOT": str(self.root / "runtime"),
            "AGENT_MEMORY_CONFIG_FILE": str(self.root / "runtime" / "missing.toml"),
            "AGENT_MEMORY_STATE_DB": str(self.root / "runtime" / "state.sqlite"),
            "AGENT_MEMORY_CLOSEOUT_LOG": str(self.root / "runtime" / "logs" / "closeout.jsonl"),
        })

        result = self.module.source_generated_index_plan(
            Path(sys.executable),
            environment,
            args,
        )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "ready")
        self.assertFalse(result["blocking"])

        (vault / "AGENTS.md").write_text("# Rules\n\nUncommitted.\n", encoding="utf-8")
        blocked = self.module.source_generated_index_plan(
            Path(sys.executable),
            environment,
            args,
        )
        self.assertFalse(blocked["ok"])
        self.assertEqual(blocked["reason_code"], "GENERATED_INDEX_MIGRATION_DIRTY_MEMORY")
        self.assertEqual(blocked["dirty_markdown"], ["AGENTS.md"])

    def test_success_has_one_prepared_and_completed_durable_transaction(self) -> None:
        args = self.args()
        with mock.patch.object(
            self.module,
            "apply",
            return_value={"ok": True, "status": "ready"},
        ):
            result = self.module.apply_with_orchestration_transaction(args)

        events = self.module._read_install_journal(self.journal(args))
        self.assertEqual([item["event"] for item in events], ["prepared", "completed"])
        self.assertEqual(events[0]["transaction_id"], events[1]["transaction_id"])
        self.assertEqual(events[0]["input_sha256"], events[1]["input_sha256"])
        self.assertEqual(result["install_transaction"]["status"], "completed")
        self.assertFalse(result["install_transaction"]["resumed"])

    def test_completed_transaction_does_not_leak_tail_into_new_transaction(self) -> None:
        args = self.args()
        paths = self.module.private_paths(args)
        projection = self.module._install_input_projection(args, paths)
        fingerprint = self.module._install_input_sha256(projection)
        old_transaction_id = "8" * 32
        journal = self.journal(args)
        for event in (
            {
                "event": "prepared",
                "transaction_id": old_transaction_id,
                "input_sha256": fingerprint,
                "original_mode": "fresh",
                "input_projection": projection,
            },
            {
                "event": "stage_started",
                "transaction_id": old_transaction_id,
                "input_sha256": fingerprint,
                "stage": "state-apply",
            },
            {
                "event": "stage_completed",
                "transaction_id": old_transaction_id,
                "input_sha256": fingerprint,
                "stage": "state-apply",
                "result": {"ok": True, "status": "applied"},
            },
            {
                "event": "completed",
                "transaction_id": old_transaction_id,
                "input_sha256": fingerprint,
                "status": "ready",
            },
        ):
            self.module._append_install_event(journal, event)

        observed: dict[str, object] = {}

        def apply_without_inherited_state(_args):
            context = self.module._ACTIVE_INSTALL_TRANSACTION
            observed["started_stages"] = set(context["started_stages"])
            observed["completed_results"] = dict(context["completed_results"])
            observed["stage_result"] = self.module._transaction_stage_started(
                "state-apply"
            )
            return {"ok": True, "status": "ready"}

        with mock.patch.object(
            self.module,
            "apply",
            side_effect=apply_without_inherited_state,
        ):
            result = self.module.apply_with_orchestration_transaction(args)

        events = self.module._read_install_journal(journal)
        self.assertEqual(observed["started_stages"], set())
        self.assertEqual(observed["completed_results"], {})
        self.assertIsNone(observed["stage_result"])
        self.assertEqual(
            [item["event"] for item in events],
            [
                "prepared",
                "stage_started",
                "stage_completed",
                "completed",
                "prepared",
                "stage_started",
                "completed",
            ],
        )
        self.assertNotEqual(
            result["install_transaction"]["transaction_id"],
            old_transaction_id,
        )
        self.assertFalse(result["install_transaction"]["resumed"])

    def test_interrupted_transaction_resumes_only_with_identical_inputs(self) -> None:
        args = self.args()
        with mock.patch.object(
            self.module,
            "apply",
            side_effect=self.module.PosixInstallError("INJECTED", "state-apply"),
        ):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(args)

        with mock.patch.object(
            self.module,
            "apply",
            return_value={"ok": True, "status": "ready"},
        ):
            resumed = self.module.apply_with_orchestration_transaction(args)

        events = self.module._read_install_journal(self.journal(args))
        self.assertEqual(
            [item["event"] for item in events],
            ["prepared", "interrupted", "resumed", "completed"],
        )
        self.assertTrue(resumed["install_transaction"]["resumed"])
        self.assertEqual(len({item["transaction_id"] for item in events}), 1)

    def test_pending_transaction_with_different_inputs_fails_before_apply(self) -> None:
        original = self.args()
        with mock.patch.object(
            self.module,
            "apply",
            side_effect=self.module.PosixInstallError("INJECTED", "runtime-install"),
        ):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(original)

        changed = self.args(app_id="different-app")
        with mock.patch.object(self.module, "apply") as apply:
            with self.assertRaises(self.module.PosixInstallError) as raised:
                self.module.apply_with_orchestration_transaction(changed)
        self.assertEqual(raised.exception.reason_code, "INSTALL_TRANSACTION_INPUT_MISMATCH")
        apply.assert_not_called()

    def supersede_evidence(self, tail: list[dict[str, object]]) -> dict[str, object]:
        prepared = tail[0]
        return {
            "schema_version": 1,
            "old_transaction_id": prepared["transaction_id"],
            "old_input_sha256": prepared["input_sha256"],
            "runtime_bundle_sha256": prepared["input_projection"]["runtime_bundle_sha256"],
            "runtime_manifest_sha256": "a" * 64,
            "runtime_transition_sha256": "b" * 64,
            "runtime_transition_phase": "preflight",
            "runtime_install_id": "c" * 64,
            "runtime_anchor_sha256": "d" * 64,
            "runtime_transactions_sha256": "e" * 64,
            "launchagent_status": "terminal",
            "launchagent_child_status": "rolled_back",
            "launchagent_transaction_id": "f" * 32,
            "launchagent_journal_events_sha256": "1" * 64,
            "launchagent_no_recovery_required": True,
        }

    def seed_recovery_required_transaction(
        self,
        args: Namespace,
        *,
        reason_code: str = "INSTALL_BACKUP_RECEIPT_INVALID",
        stage: str = "state-apply",
        stage_events: tuple[tuple[str, str], ...] = (),
    ) -> tuple[str, dict[str, object]]:
        paths = self.module.private_paths(args)
        projection = self.module._install_input_projection(args, paths)
        fingerprint = self.module._install_input_sha256(projection)
        transaction_id = "9" * 32
        journal = self.journal(args)
        self.module._append_install_event(
            journal,
            {
                "event": "prepared",
                "transaction_id": transaction_id,
                "input_sha256": fingerprint,
                "original_mode": "upgrade",
                "input_projection": projection,
            },
        )
        for event, event_stage in stage_events:
            self.module._append_install_event(
                journal,
                {
                    "event": event,
                    "transaction_id": transaction_id,
                    "input_sha256": fingerprint,
                    "stage": event_stage,
                    **(
                        {"result": {"ok": True, "status": "completed"}}
                        if event == "stage_completed"
                        else {}
                    ),
                },
            )
        self.module._append_install_event(
            journal,
            {
                "event": "recovery_required",
                "transaction_id": transaction_id,
                "input_sha256": fingerprint,
                "reason_code": reason_code,
                "stage": stage,
            },
        )
        return transaction_id, projection

    @staticmethod
    def live_recovery_stage_events() -> tuple[tuple[str, str], ...]:
        # Read-only fixture copied from the failed live transaction's event order.
        stages = (
            "configured-paths",
            "config-plan",
            "state-plan",
            "audit-plan",
            "generated-index-plan",
            "backup-parents",
            "runtime-install",
            "config-plan",
            "configured-paths",
        )
        return tuple(
            event
            for stage in stages
            for event in (("stage_started", stage), ("stage_completed", stage))
        )

    def recovery_runtime_attestation(
        self,
        projection: dict[str, object],
    ) -> dict[str, object]:
        return {
            "healthy": True,
            "bundle_sha256": projection["runtime_bundle_sha256"],
            "manifest_sha256": "a" * 64,
            "transition_sha256": "b" * 64,
            "transition_phase": "preflight",
            "install_id": "c" * 64,
            "runtime_anchor_sha256": "d" * 64,
            "runtime_transactions_sha256": "e" * 64,
        }

    def no_current_launchagent_mutation(self) -> dict[str, object]:
        return {
            "healthy": True,
            "status": "terminal",
            "reason_code": "",
            "child_status": "completed",
            "transaction_id": "f" * 32,
            "journal_path": "/private/prior-launchagent-transaction.jsonl",
            "journal_events_sha256": "1" * 64,
            "recovery_required_seen": False,
        }

    def test_exact_state_receipt_recovery_can_be_explicitly_superseded(self) -> None:
        batch = self.root / "runtime" / "backups" / "failed-attempt"
        original = self.args(
            config_backup=str(batch / "config.toml"),
            state_backup=str(batch / "state.sqlite"),
            audit_backup=str(batch / "audit.sqlite"),
            hook_backup_dir=str(batch / "hooks"),
            launchagent_backup_dir=str(batch / "launchagent"),
        )
        stage_events = self.live_recovery_stage_events()
        transaction_id, projection = self.seed_recovery_required_transaction(
            original,
            stage_events=stage_events,
        )
        replacement = self.args(
            config_backup=original.config_backup,
            state_backup=original.state_backup,
            audit_backup=original.audit_backup,
            hook_backup_dir=original.hook_backup_dir,
            launchagent_backup_dir=original.launchagent_backup_dir,
            app_id="replacement",
            supersede_interrupted=transaction_id,
        )
        with (
            mock.patch.object(
                self.module.runtime_installer,
                "attest_installed_runtime_static",
                return_value=self.recovery_runtime_attestation(projection),
            ) as runtime_attestation,
            mock.patch.object(
                self.module,
                "launchagent_transaction_health",
                return_value=self.no_current_launchagent_mutation(),
            ),
            mock.patch.object(
                self.module,
                "apply",
                return_value={"ok": True, "status": "ready"},
            ) as apply,
        ):
            result = self.module.apply_with_orchestration_transaction(replacement)

        runtime_attestation.assert_called_once_with(
            self.module.private_paths(original)["config_root"]
        )
        apply.assert_called_once_with(replacement)
        events = self.module._read_install_journal(self.journal(original))
        validated_tail = self.module._active_install_tail(events)
        self.assertEqual(
            [item["event"] for item in events],
            [
                "prepared",
                *(event for event, _stage in stage_events),
                "recovery_required",
                "superseded",
                "prepared",
                "completed",
            ],
        )
        superseded_index = len(stage_events) + 2
        superseded = events[superseded_index]
        evidence = superseded["evidence"]
        self.assertEqual(evidence["supersede_basis_event"], "recovery_required")
        self.assertEqual(
            evidence["recovery_supersede_policy"],
            self.module.RECOVERY_SUPERSEDE_POLICY,
        )
        self.assertEqual(
            evidence["started_stages"],
            [stage for event, stage in stage_events if event == "stage_started"],
        )
        self.assertEqual(
            evidence["completed_stages"],
            [stage for event, stage in stage_events if event == "stage_completed"],
        )
        self.assertEqual(evidence["backup_receipt_stages_started"], [])
        self.assertEqual(evidence["backup_receipt_stages_completed"], [])
        self.assertEqual(evidence["mutating_stages_started"], ["backup-parents"])
        self.assertEqual(evidence["mutating_stages_completed"], ["backup-parents"])
        self.assertEqual(len(evidence["specified_backup_targets"]), 5)
        self.assertTrue(
            all(item["absent"] is True for item in evidence["specified_backup_targets"])
        )
        self.assertEqual(
            superseded["evidence_sha256"],
            self.module._install_input_sha256(evidence),
        )
        self.assertEqual(validated_tail[-1]["event"], "completed")
        self.assertFalse(result["install_transaction"]["resumed"])

        tampered = copy.deepcopy(events)
        tampered[superseded_index]["evidence"]["completed_stages"] = [
            "runtime-install"
        ]
        tampered[superseded_index]["evidence_sha256"] = (
            self.module._install_input_sha256(
                tampered[superseded_index]["evidence"]
            )
        )
        with self.assertRaises(self.module.PosixInstallError) as invalid:
            self.module._active_install_tail(tampered)
        self.assertEqual(invalid.exception.reason_code, "INSTALL_JOURNAL_INVALID")

        malicious_history = copy.deepcopy(events)
        malicious_history[2]["stage"] = "state-apply"
        malicious_evidence = malicious_history[superseded_index]["evidence"]
        malicious_evidence["stage_lifecycle"][1]["stage"] = "state-apply"
        malicious_evidence["completed_stages"][0] = "state-apply"
        malicious_evidence["backup_receipt_stages_completed"] = ["state-apply"]
        malicious_evidence["mutating_stages_completed"] = [
            "backup-parents",
            "state-apply",
        ]
        malicious_evidence["disallowed_stage_events"] = ["state-apply"]
        malicious_history[superseded_index]["evidence_sha256"] = (
            self.module._install_input_sha256(malicious_evidence)
        )
        with self.assertRaises(self.module.PosixInstallError) as invalid_history:
            self.module._active_install_tail(malicious_history)
        self.assertEqual(
            invalid_history.exception.reason_code,
            "INSTALL_JOURNAL_INVALID",
        )

    def test_recovery_supersede_rejects_started_mutating_stage(self) -> None:
        original = self.args()
        transaction_id, _projection = self.seed_recovery_required_transaction(
            original,
            stage_events=(("stage_started", "state-apply"),),
        )
        replacement = self.args(
            app_id="replacement",
            supersede_interrupted=transaction_id,
        )

        with mock.patch.object(self.module, "apply") as apply, self.assertRaises(
            self.module.PosixInstallError
        ) as raised:
            self.module.apply_with_orchestration_transaction(replacement)

        self.assertEqual(
            raised.exception.reason_code,
            "INSTALL_RECOVERY_SUPERSEDE_UNSAFE_STAGE_EVENT",
        )
        apply.assert_not_called()
        self.assertEqual(
            self.module._read_install_journal(self.journal(original))[-1]["event"],
            "recovery_required",
        )

    def assert_recovery_stage_events_blocked(
        self,
        stage_events: tuple[tuple[str, str], ...],
        expected_reason: str,
    ) -> None:
        original = self.args()
        transaction_id, _projection = self.seed_recovery_required_transaction(
            original,
            stage_events=stage_events,
        )
        replacement = self.args(
            app_id="replacement",
            supersede_interrupted=transaction_id,
        )
        with mock.patch.object(self.module, "apply") as apply, self.assertRaises(
            self.module.PosixInstallError
        ) as raised:
            self.module.apply_with_orchestration_transaction(replacement)
        self.assertEqual(raised.exception.reason_code, expected_reason)
        apply.assert_not_called()
        self.assertEqual(
            self.module._read_install_journal(self.journal(original))[-1]["event"],
            "recovery_required",
        )

    def test_recovery_supersede_rejects_orphan_state_apply_completed(self) -> None:
        self.assert_recovery_stage_events_blocked(
            (("stage_completed", "state-apply"),),
            "INSTALL_RECOVERY_SUPERSEDE_UNSAFE_STAGE_EVENT",
        )

    def test_recovery_supersede_rejects_orphan_safe_stage_completed(self) -> None:
        self.assert_recovery_stage_events_blocked(
            (("stage_completed", "configured-paths"),),
            "INSTALL_RECOVERY_SUPERSEDE_STAGE_HISTORY_INVALID",
        )

    def test_recovery_supersede_rejects_disallowed_completed_event(self) -> None:
        self.assert_recovery_stage_events_blocked(
            (
                ("stage_started", "configured-paths"),
                ("stage_completed", "state-apply"),
            ),
            "INSTALL_RECOVERY_SUPERSEDE_UNSAFE_STAGE_EVENT",
        )

    def test_recovery_supersede_rejects_duplicate_completed_event(self) -> None:
        self.assert_recovery_stage_events_blocked(
            (
                ("stage_started", "configured-paths"),
                ("stage_completed", "configured-paths"),
                ("stage_completed", "configured-paths"),
            ),
            "INSTALL_RECOVERY_SUPERSEDE_STAGE_HISTORY_INVALID",
        )

    def test_recovery_supersede_rejects_reason_mismatch_permanently(self) -> None:
        original = self.args()
        transaction_id, _projection = self.seed_recovery_required_transaction(
            original,
            reason_code="INSTALL_BACKUP_RECEIPT_MISMATCH",
        )
        replacement = self.args(
            app_id="replacement",
            supersede_interrupted=transaction_id,
        )

        with mock.patch.object(self.module, "apply") as apply, self.assertRaises(
            self.module.PosixInstallError
        ) as raised:
            self.module.apply_with_orchestration_transaction(replacement)

        self.assertEqual(raised.exception.reason_code, "INSTALL_RECOVERY_REQUIRED")
        apply.assert_not_called()
        self.assertEqual(
            self.module._read_install_journal(self.journal(original))[-1]["event"],
            "recovery_required",
        )

    def test_recovery_supersede_rejects_existing_backup_target(self) -> None:
        backup = self.root / "runtime" / "backups" / "used" / "state.sqlite"
        original = self.args(state_backup=str(backup))
        transaction_id, _projection = self.seed_recovery_required_transaction(
            original,
            stage_events=self.live_recovery_stage_events(),
        )
        backup.parent.mkdir(mode=0o700, parents=True)
        backup.write_bytes(b"must-not-overwrite")
        backup.chmod(0o600)
        replacement = self.args(
            state_backup=str(self.root / "runtime" / "backups" / "new" / "state.sqlite"),
            app_id="replacement",
            supersede_interrupted=transaction_id,
        )

        with mock.patch.object(self.module, "apply") as apply, self.assertRaises(
            self.module.PosixInstallError
        ) as raised:
            self.module.apply_with_orchestration_transaction(replacement)

        self.assertEqual(
            raised.exception.reason_code,
            "INSTALL_RECOVERY_SUPERSEDE_BACKUP_TARGET_EXISTS",
        )
        self.assertEqual(raised.exception.evidence["path"], str(backup))
        apply.assert_not_called()
        self.assertEqual(
            self.module._read_install_journal(self.journal(original))[-1]["event"],
            "recovery_required",
        )

    def test_explicit_supersede_terminalizes_proven_interrupted_then_applies_new_input(self) -> None:
        original = self.args()
        with mock.patch.object(
            self.module,
            "apply",
            side_effect=self.module.PosixInstallError("INJECTED", "publish-ready"),
        ):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(original)

        interrupted_id = self.module._read_install_journal(self.journal(original))[0][
            "transaction_id"
        ]
        changed = self.args(
            app_id="new-app",
            supersede_interrupted=interrupted_id,
        )
        with (
            mock.patch.object(
                self.module,
                "_prove_interrupted_transaction_supersedable",
                side_effect=lambda **kwargs: self.supersede_evidence(kwargs["tail"]),
            ),
            mock.patch.object(
                self.module,
                "apply",
                return_value={"ok": True, "status": "ready"},
            ),
        ):
            result = self.module.apply_with_orchestration_transaction(changed)

        events = self.module._read_install_journal(self.journal(changed))
        self.assertEqual(
            [item["event"] for item in events],
            ["prepared", "interrupted", "superseded", "prepared", "completed"],
        )
        self.assertEqual(
            events[2]["replacement_transaction_id"],
            events[3]["transaction_id"],
        )
        self.assertEqual(
            events[2]["replacement_input_sha256"],
            events[3]["input_sha256"],
        )
        self.assertEqual(
            events[2]["evidence_sha256"],
            self.module._install_input_sha256(events[2]["evidence"]),
        )
        self.assertFalse(result["install_transaction"]["resumed"])

    def test_supersede_proof_failure_appends_no_event(self) -> None:
        original = self.args()
        with mock.patch.object(
            self.module,
            "apply",
            side_effect=self.module.PosixInstallError("INJECTED", "publish-ready"),
        ):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(original)
        journal = self.journal(original)
        before = journal.read_bytes()

        interrupted_id = self.module._read_install_journal(journal)[0]["transaction_id"]
        changed = self.args(
            app_id="new-app",
            supersede_interrupted=interrupted_id,
        )
        with (
            mock.patch.object(
                self.module,
                "_prove_interrupted_transaction_supersedable",
                side_effect=self.module.PosixInstallError(
                    "INSTALL_SUPERSEDE_LAUNCHAGENT_EVIDENCE_INVALID",
                    "orchestration-supersede",
                ),
            ),
            mock.patch.object(self.module, "apply") as apply,
        ):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(changed)
        self.assertEqual(journal.read_bytes(), before)
        apply.assert_not_called()

    def test_pre_runtime_interruption_can_be_superseded_without_launchagent_child(self) -> None:
        args = self.args()
        paths = self.module.private_paths(args)
        projection = self.module._install_input_projection(args, paths)
        fingerprint = self.module._install_input_sha256(projection)
        transaction_id = "a" * 32
        tail = [
            {
                "event": "prepared",
                "transaction_id": transaction_id,
                "input_sha256": fingerprint,
                "input_projection": projection,
            },
            {
                "event": "stage_started",
                "transaction_id": transaction_id,
                "input_sha256": fingerprint,
                "stage": "backup-parents",
            },
            {
                "event": "interrupted",
                "transaction_id": transaction_id,
                "input_sha256": fingerprint,
                "reason_code": "BACKUP_PARENT_SYMLINK",
                "stage": "backup-parents",
            },
        ]
        launch_health = {
            "healthy": True,
            "status": "none",
            "child_status": "missing",
            "recovery_required_seen": False,
        }

        with mock.patch.object(
            self.module.runtime_installer,
            "attest_installed_runtime_static",
        ) as runtime_health, mock.patch.object(
            self.module,
            "launchagent_transaction_health",
            return_value=launch_health,
        ):
            evidence = self.module._prove_interrupted_transaction_supersedable(
                tail=tail,
                config_root=paths["config_root"],
            )

        runtime_health.assert_not_called()
        self.assertFalse(evidence["runtime_stage_started"])
        self.assertFalse(evidence["launchagent_stage_started"])
        self.assertTrue(evidence["launchagent_no_recovery_required"])

    def test_supersede_cannot_bypass_tampered_completed_backup_receipt(self) -> None:
        batch = self.root / "runtime" / "backups" / "old-receipt"
        batch.mkdir(mode=0o700, parents=True)
        backup = batch / "state.sqlite"
        original = self.args(state_backup=str(backup))

        def complete_backup_then_interrupt(_args):
            backup.write_bytes(b"trusted")
            backup.chmod(0o600)
            self.module._transaction_stage_completed(
                "state-apply",
                {"ok": True, "status": "applied", "backup": {"path": str(backup)}},
            )
            raise self.module.PosixInstallError("INJECTED", "publish-ready")

        with mock.patch.object(self.module, "apply", side_effect=complete_backup_then_interrupt):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(original)

        backup.write_bytes(b"tampered")
        backup.chmod(0o600)
        events = self.module._read_install_journal(self.journal(original))
        interrupted_id = events[0]["transaction_id"]
        replacement = self.args(
            state_backup=str(self.root / "runtime" / "backups" / "new" / "state.sqlite"),
            app_id="replacement",
            supersede_interrupted=interrupted_id,
        )
        with mock.patch.object(self.module, "apply") as apply, self.assertRaises(
            self.module.PosixInstallError
        ) as raised:
            self.module.apply_with_orchestration_transaction(replacement)

        self.assertEqual(raised.exception.reason_code, "INSTALL_BACKUP_RECEIPT_MISMATCH")
        apply.assert_not_called()
        after = self.module._read_install_journal(self.journal(original))
        self.assertEqual(after[-1]["event"], "recovery_required")

    def test_superseded_crash_window_resumes_only_bound_replacement(self) -> None:
        original = self.args()
        with mock.patch.object(
            self.module,
            "apply",
            side_effect=self.module.PosixInstallError("INJECTED", "publish-ready"),
        ):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(original)

        interrupted_id = self.module._read_install_journal(self.journal(original))[0][
            "transaction_id"
        ]
        changed = self.args(
            app_id="new-app",
            supersede_interrupted=interrupted_id,
        )
        real_append = self.module._append_install_event
        superseded_written = False

        def crash_before_replacement_prepared(path, event):
            nonlocal superseded_written
            if event["event"] == "prepared" and superseded_written:
                raise OSError("injected crash")
            real_append(path, event)
            if event["event"] == "superseded":
                superseded_written = True

        with (
            mock.patch.object(
                self.module,
                "_prove_interrupted_transaction_supersedable",
                side_effect=lambda **kwargs: self.supersede_evidence(kwargs["tail"]),
            ),
            mock.patch.object(
                self.module,
                "_append_install_event",
                side_effect=crash_before_replacement_prepared,
            ),
        ):
            with self.assertRaises(OSError):
                self.module.apply_with_orchestration_transaction(changed)

        replacement = self.module._read_install_journal(self.journal(changed))[-1]
        retry = self.args(app_id="new-app")
        with mock.patch.object(
            self.module,
            "apply",
            return_value={"ok": True, "status": "ready"},
        ):
            result = self.module.apply_with_orchestration_transaction(retry)
        self.assertEqual(
            result["install_transaction"]["transaction_id"],
            replacement["replacement_transaction_id"],
        )

    def test_recovery_required_transaction_cannot_be_downgraded_to_resume(self) -> None:
        args = self.args()
        with mock.patch.object(
            self.module,
            "apply",
            side_effect=self.module.PosixInstallError(
                "AUDIT_LAUNCHAGENT_RECOVERY_REQUIRED",
                "audit-launchagent-rollback",
            ),
        ):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(args)

        with mock.patch.object(self.module, "apply") as apply:
            with self.assertRaises(self.module.PosixInstallError) as raised:
                self.module.apply_with_orchestration_transaction(args)
        self.assertEqual(raised.exception.reason_code, "INSTALL_RECOVERY_REQUIRED")
        apply.assert_not_called()
        self.assertEqual(
            self.module._read_install_journal(self.journal(args))[-1]["event"],
            "recovery_required",
        )

    def test_backup_receipt_mismatch_is_terminal_recovery_required(self) -> None:
        args = self.args()
        with mock.patch.object(
            self.module,
            "apply",
            side_effect=self.module.PosixInstallError(
                "INSTALL_BACKUP_RECEIPT_MISMATCH",
                "state-apply",
            ),
        ):
            with self.assertRaises(self.module.PosixInstallError):
                self.module.apply_with_orchestration_transaction(args)

        events = self.module._read_install_journal(self.journal(args))
        self.assertEqual([item["event"] for item in events], ["prepared", "recovery_required"])
        self.assertEqual(events[-1]["reason_code"], "INSTALL_BACKUP_RECEIPT_MISMATCH")

    def test_all_backup_receipts_are_rechecked_immediately_before_completed(self) -> None:
        batch = self.root / "runtime" / "backups" / "terminal-check"
        batch.mkdir(mode=0o700, parents=True)
        backup = batch / "state.sqlite"
        args = self.args(state_backup=str(backup))

        def applied_then_tampered(_args):
            backup.write_bytes(b"trusted")
            backup.chmod(0o600)
            self.module._transaction_stage_completed(
                "state-apply",
                {"ok": True, "status": "applied", "backup": {"path": str(backup)}},
            )
            backup.write_bytes(b"tampered")
            backup.chmod(0o600)
            return {"ok": True, "status": "ready"}

        with mock.patch.object(self.module, "apply", side_effect=applied_then_tampered):
            with self.assertRaises(self.module.PosixInstallError) as raised:
                self.module.apply_with_orchestration_transaction(args)

        self.assertEqual(raised.exception.reason_code, "INSTALL_BACKUP_RECEIPT_MISMATCH")
        events = self.module._read_install_journal(self.journal(args))
        self.assertEqual(
            [item["event"] for item in events],
            ["prepared", "stage_completed", "recovery_required"],
        )

    def test_source_drift_during_apply_is_terminal_recovery_required(self) -> None:
        args = self.args()
        before = {"runtime_source_sha256": "a" * 64}
        after = {"runtime_source_sha256": "b" * 64}
        with mock.patch.object(
            self.module,
            "_install_input_projection",
            side_effect=[before, after],
        ), mock.patch.object(
            self.module,
            "apply",
            return_value={"ok": True, "status": "ready"},
        ):
            with self.assertRaises(self.module.PosixInstallError) as raised:
                self.module.apply_with_orchestration_transaction(args)

        self.assertEqual(raised.exception.reason_code, "INSTALL_INPUT_CHANGED_DURING_APPLY")
        events = self.module._read_install_journal(self.journal(args))
        self.assertEqual([item["event"] for item in events], ["prepared", "recovery_required"])
        self.assertEqual(events[-1]["reason_code"], "INSTALL_INPUT_CHANGED_DURING_APPLY")

    def test_total_install_lock_rejects_concurrent_apply(self) -> None:
        args = self.args()
        paths = self.module.private_paths(args)
        lock = paths["config_root"] / "locks" / "install-orchestration.lock"
        with self.module.private_lock(
            lock,
            timeout=0.0,
            timeout_message="test holder",
        ):
            with mock.patch.object(self.module, "apply") as apply:
                with self.assertRaises(self.module.PosixInstallError) as raised:
                    self.module.apply_with_orchestration_transaction(args)
        self.assertEqual(raised.exception.reason_code, "INSTALL_ALREADY_RUNNING")
        apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
