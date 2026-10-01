from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_host_automation as automation
import agent_memory_doctor as doctor
import agent_memory_migrate as migrate


class HostAutomationClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.runtime = self.root / "runtime"
        self.python = self.runtime / ".venv" / "bin" / "python"
        (self.runtime / "scripts").mkdir(parents=True)
        self.python.parent.mkdir(parents=True)
        self.python.write_text("python\n", encoding="utf-8")
        (self.runtime / "scripts" / "memoryctl").write_text("memoryctl\n", encoding="utf-8")
        self.spec = automation.HookSpec(
            "codex",
            "stop-hook",
            (
                "--protocol", "codex", "--event", "stop-hook",
                "--auto-closeout", "--timeout", "300",
            ),
            320,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def entry(self, command: str, timeout: int = 320) -> dict[str, object]:
        return {"type": "command", "command": command, "timeout": timeout}

    def classify(self, entry: object) -> automation.RouteClassification:
        return automation.classify_hook_entry(
            entry,
            runtime_python=self.python,
            runtime_root=self.runtime,
            spec=self.spec,
        )

    def test_exact_managed_memoryctl_is_the_only_canonical_route(self) -> None:
        command = automation.canonical_hook_command(self.python, self.runtime, self.spec)
        self.assertEqual(self.classify(self.entry(command)).kind, automation.CANONICAL)
        self.assertEqual(self.classify(self.entry(command, timeout=319)).kind, automation.AMBIGUOUS)
        self.assertEqual(
            self.classify(self.entry(command + " --unexpected")).kind,
            automation.AMBIGUOUS,
        )

    def test_direct_script_and_bounded_wrapper_are_legacy(self) -> None:
        direct = (
            f"/usr/bin/python3 {self.runtime}/scripts/agent_memory_stop_hook.py "
            "--actor codex --protocol codex --auto-closeout --timeout 300"
        )
        self.assertEqual(self.classify(self.entry(direct)).kind, automation.LEGACY)

        wrapper = self.root / "on-stop-memory.sh"
        wrapper.write_text(
            "#!/bin/sh\nexec /usr/bin/python3 "
            f"{self.runtime}/scripts/agent_memory_stop_hook.py --actor codex\n",
            encoding="utf-8",
        )
        result = self.classify(self.entry(str(wrapper)))
        self.assertEqual(result.kind, automation.LEGACY)
        self.assertEqual(result.wrapper_path, str(wrapper))

        direct_with_argument = self.classify(
            self.entry(f"{wrapper} --ignored-wrapper-argument")
        )
        self.assertEqual(direct_with_argument.kind, automation.LEGACY)
        self.assertEqual(direct_with_argument.wrapper_path, str(wrapper))

        shell_result = self.classify(self.entry(f"/bin/bash {wrapper}"))
        self.assertEqual(shell_result.kind, automation.LEGACY)
        self.assertEqual(shell_result.wrapper_path, str(wrapper))

        shell_c_result = self.classify(
            self.entry(f"/bin/sh -c '{wrapper} --ignored-wrapper-argument'")
        )
        self.assertEqual(shell_c_result.kind, automation.LEGACY)
        self.assertEqual(shell_c_result.wrapper_path, str(wrapper))

    @unittest.skipIf(os.name == "nt", "POSIX symlink classification")
    def test_generic_symlink_cannot_hide_duplicate_hook_wrapper(self) -> None:
        target = self.root / "generic-target"
        target.write_text(
            "#!/bin/sh\nexec memoryctl --actor codex stop-hook --protocol codex\n",
            encoding="utf-8",
        )
        alias = self.root / "notify-helper"
        alias.symlink_to(target)

        result = self.classify(self.entry(str(alias)))
        self.assertEqual(result.kind, automation.AMBIGUOUS)
        self.assertEqual(result.reason_code, "HOOK_WRAPPER_SYMLINK")
        self.assertEqual(result.wrapper_path, str(alias))

    def test_wrong_actor_route_is_ambiguous_and_notification_is_unrelated(self) -> None:
        wrong = automation.canonical_hook_command(
            self.python,
            self.runtime,
            automation.HookSpec("claude", "stop-hook", self.spec.forwarded, 320),
        )
        self.assertEqual(self.classify(self.entry(wrong)).kind, automation.AMBIGUOUS)
        self.assertEqual(
            self.classify(self.entry(str(self.root / "notify-desktop"))).kind,
            automation.UNRELATED,
        )

    def test_event_health_requires_one_canonical_and_zero_legacy_or_ambiguous(self) -> None:
        canonical = self.entry(
            automation.canonical_hook_command(self.python, self.runtime, self.spec)
        )
        wrapper = self.root / "legacy.sh"
        wrapper.write_text("exec agent_memory_stop_hook.py --actor codex\n", encoding="utf-8")
        hooks = {"Stop": [{"hooks": [canonical, self.entry(str(wrapper)), self.entry("notify")]}]}
        detail = automation.classify_hook_event(
            hooks,
            "Stop",
            runtime_python=self.python,
            runtime_root=self.runtime,
            spec=self.spec,
        )
        self.assertFalse(detail["healthy"])
        self.assertEqual(detail["canonical_count"], 1)
        self.assertEqual(detail["legacy_count"], 1)
        self.assertEqual(detail["unrelated_count"], 1)
        self.assertEqual(detail["wrapper_paths"], [str(wrapper)])

        shell_wrapped = {
            "Stop": [{
                "hooks": [
                    canonical,
                    self.entry(f"/bin/bash {wrapper}"),
                ]
            }]
        }
        shell_detail = automation.classify_hook_event(
            shell_wrapped,
            "Stop",
            runtime_python=self.python,
            runtime_root=self.runtime,
            spec=self.spec,
        )
        self.assertFalse(shell_detail["healthy"])
        self.assertEqual(shell_detail["legacy_count"], 1)

    def test_disabled_canonical_route_is_never_healthy(self) -> None:
        canonical = self.entry(
            automation.canonical_hook_command(self.python, self.runtime, self.spec)
        )
        for hooks in (
            {"Stop": [{"enabled": False, "hooks": [canonical]}]},
            {"Stop": [{"hooks": [{**canonical, "disabled": True}]}]},
            {"enabled": False, "Stop": [{"hooks": [canonical]}]},
        ):
            detail = automation.classify_hook_event(
                hooks,
                "Stop",
                runtime_python=self.python,
                runtime_root=self.runtime,
                spec=self.spec,
            )
            self.assertFalse(detail["healthy"], detail)
            self.assertEqual(detail["canonical_count"], 0)
            self.assertGreaterEqual(detail["ambiguous_count"], 1)
            self.assertGreaterEqual(detail["disabled_count"], 1)

    def test_matcher_scoped_canonical_lifecycle_route_is_never_healthy(self) -> None:
        canonical = self.entry(
            automation.canonical_hook_command(self.python, self.runtime, self.spec)
        )
        detail = automation.classify_hook_event(
            {"Stop": [{"matcher": "tool", "hooks": [canonical]}]},
            "Stop",
            runtime_python=self.python,
            runtime_root=self.runtime,
            spec=self.spec,
        )
        self.assertFalse(detail["healthy"])
        self.assertEqual(detail["canonical_count"], 0)
        self.assertEqual(detail["ambiguous_count"], 1)
        self.assertEqual(detail["reason_counts"], {"HOOK_ROUTE_MATCHER_SCOPED": 1})

    def test_windows_managed_memoryctl_is_canonical_and_wrapper_is_legacy(self) -> None:
        command = automation.canonical_windows_hook_command(self.runtime, self.spec)
        result = self.classify(self.entry(command))
        self.assertEqual(result.kind, automation.CANONICAL, result)
        self.assertEqual(result.reason_code, "HOOK_WINDOWS_MEMORYCTL_CANONICAL")
        self.assertEqual(
            automation.split_windows_command(command)[:4],
            [
                str(self.runtime / ".venv" / "Scripts" / "python.exe"),
                "-I",
                "-S",
                str(self.runtime / "scripts" / "memoryctl"),
            ],
        )

        wrong_actor = command.replace("--actor codex", "--actor claude")
        self.assertEqual(self.classify(self.entry(wrong_actor)).kind, automation.AMBIGUOUS)
        missing_auto = command.replace(" --auto-closeout", "")
        self.assertEqual(self.classify(self.entry(missing_auto)).kind, automation.AMBIGUOUS)
        self.assertEqual(
            self.classify(self.entry(command, timeout=20)).kind,
            automation.AMBIGUOUS,
        )
        legacy = subprocess.list2cmdline([
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(self.runtime / "scripts" / "stop-hook.ps1"),
            "-Actor", "codex", "-Protocol", "codex", "-AutoCloseout",
        ])
        legacy_result = self.classify(self.entry(legacy))
        self.assertEqual(legacy_result.kind, automation.LEGACY, legacy_result)
        self.assertEqual(legacy_result.reason_code, "HOOK_WINDOWS_WRAPPER_LEGACY")

    def test_windows_non_auto_installer_mode_has_its_own_exact_contract(self) -> None:
        spec = automation.codex_stop_hook_spec(auto_closeout=False)
        command = automation.canonical_windows_hook_command(self.runtime, spec)
        entry = self.entry(command, timeout=20)
        result = automation.classify_hook_entry(
            entry,
            runtime_python=self.python,
            runtime_root=self.runtime,
            spec=spec,
        )
        self.assertEqual(result.kind, automation.CANONICAL, result)
        self.assertNotIn("--auto-closeout", command)

    def test_windows_installer_entry_classifier_is_private_and_fail_closed(self) -> None:
        classifier = SCRIPTS / "agent_memory_host_automation.py"
        base_command = [
            sys.executable,
            str(classifier),
            "classify-codex-hook-entry",
            "--runtime-root",
            str(self.runtime),
            "--runtime-python",
            str(self.python),
            "--auto-closeout",
            "--json",
        ]
        sensitive_marker = "hook-command-output-sentinel"
        canonical = subprocess.run(
            base_command,
            input=json.dumps(self.entry(
                automation.canonical_windows_hook_command(self.runtime, self.spec)
            )),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(canonical.returncode, 0, canonical.stderr)
        self.assertEqual(
            json.loads(canonical.stdout),
            {
                "kind": automation.CANONICAL,
                "reason_code": "HOOK_WINDOWS_MEMORYCTL_CANONICAL",
                "agent_memory_route": True,
            },
        )

        direct_legacy = {
            "type": "command",
            "command": (
                f"/usr/bin/python3 {self.runtime}/scripts/agent_memory_stop_hook.py "
                f"--actor codex --protocol codex --marker {sensitive_marker}"
            ),
            "timeout": 320,
        }
        legacy = subprocess.run(
            base_command,
            input=json.dumps(direct_legacy),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        legacy_payload = json.loads(legacy.stdout)
        self.assertEqual(
            legacy_payload,
            {
                "kind": automation.LEGACY,
                "reason_code": "HOOK_DIRECT_SCRIPT_LEGACY",
                "agent_memory_route": True,
            },
        )
        self.assertNotIn(sensitive_marker, legacy.stdout + legacy.stderr)

        unrelated = subprocess.run(
            base_command,
            input=json.dumps({
                "type": "command",
                "command": f"notify-desktop --marker {sensitive_marker}",
                "timeout": 5,
            }),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(unrelated.returncode, 0, unrelated.stderr)
        self.assertEqual(
            json.loads(unrelated.stdout),
            {
                "kind": automation.UNRELATED,
                "reason_code": "HOOK_COMMAND_UNRELATED",
                "agent_memory_route": False,
            },
        )
        self.assertNotIn(sensitive_marker, unrelated.stdout + unrelated.stderr)

        ambiguous_third_party = subprocess.run(
            base_command,
            input=json.dumps({
                "type": "command",
                "command": (
                    '"C:\\OtherPython\\python.exe" -I -S '
                    '"C:\\ThirdParty\\memoryctl" --actor vendor search'
                ),
                "timeout": 20,
            }),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(ambiguous_third_party.returncode, 0, ambiguous_third_party.stderr)
        self.assertEqual(
            json.loads(ambiguous_third_party.stdout),
            {
                "kind": automation.AMBIGUOUS,
                "reason_code": "HOOK_WINDOWS_MEMORYCTL_ROUTE_MISMATCH",
                "agent_memory_route": False,
            },
        )

        vendor_wrapper = subprocess.run(
            base_command,
            input=json.dumps({
                "type": "command",
                "command": subprocess.list2cmdline([
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    "C:\\Vendor\\stop-hook.ps1",
                    "-Actor",
                    "codex",
                    "-Protocol",
                    "codex",
                    "-AutoCloseout",
                ]),
                "timeout": 320,
            }),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(vendor_wrapper.returncode, 0, vendor_wrapper.stderr)
        self.assertEqual(
            json.loads(vendor_wrapper.stdout),
            {
                "kind": automation.AMBIGUOUS,
                "reason_code": "HOOK_WINDOWS_WRAPPER_COMMAND_MISMATCH",
                "agent_memory_route": False,
            },
        )

        invalid = subprocess.run(
            base_command,
            input=f'{{"command":"{sensitive_marker}"',
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(
            json.loads(invalid.stdout),
            {
                "kind": automation.AMBIGUOUS,
                "reason_code": "HOOK_ENTRY_INPUT_INVALID",
                "agent_memory_route": False,
            },
        )
        self.assertNotIn(sensitive_marker, invalid.stdout + invalid.stderr)

        oversized = subprocess.run(
            base_command,
            input="x" * (automation.HOOK_ENTRY_INPUT_MAX_BYTES + 1),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(oversized.returncode, 2)
        self.assertEqual(
            json.loads(oversized.stdout),
            {
                "kind": automation.AMBIGUOUS,
                "reason_code": "HOOK_ENTRY_INPUT_TOO_LARGE",
                "agent_memory_route": False,
            },
        )
        self.assertEqual(oversized.stderr, "")

    def test_doctor_installer_and_publish_ready_share_windows_classification(self) -> None:
        command = automation.canonical_windows_hook_command(self.runtime, self.spec)
        payload = {"hooks": {"Stop": [{"hooks": [self.entry(command)]}]}}
        hooks_path = self.root / ".codex" / "hooks.json"
        hooks_path.parent.mkdir(parents=True)
        hooks_path.write_text(json.dumps(payload), encoding="utf-8")
        (hooks_path.parent / "config.toml").write_text(
            "[features]\nhooks = true\n",
            encoding="utf-8",
        )

        verification = automation.verify_codex_hooks_file(
            hooks_path,
            runtime_root=self.runtime,
            runtime_python=self.python,
        )
        self.assertTrue(verification["ok"], verification)

        with (
            mock.patch.object(doctor, "REPO_ROOT", self.runtime),
            mock.patch.object(doctor, "PYTHON", self.python),
        ):
            healthy, detail = doctor.codex_hook_semantics(payload["hooks"])
        self.assertTrue(healthy, detail)
        self.assertEqual(detail["canonical_count"], 1)

        with (
            mock.patch.object(migrate.Path, "home", return_value=self.root),
            mock.patch.object(migrate, "RUNTIME_ROOT", self.runtime),
        ):
            publish = migrate._host_hook_health(
                no_host_hooks=False,
                required_hosts=("codex",),
                runtime_python=self.python,
            )
        self.assertTrue(publish["verified"])
        self.assertTrue(publish["codex"]["classification"]["healthy"])

    def test_publish_ready_host_selection_is_sorted_and_unique_for_both_cli_forms(self) -> None:
        cases = (
            (
                ["verify", "--publish-ready", "--require-host-hooks", "--json"],
                ("claude", "codex"),
            ),
            (
                [
                    "verify", "--publish-ready",
                    "--require-host-hook", "codex",
                    "--require-host-hook", "claude",
                    "--require-host-hook", "codex",
                    "--json",
                ],
                ("claude", "codex"),
            ),
        )
        for argv, expected in cases:
            with self.subTest(argv=argv):
                with (
                    mock.patch.object(sys, "argv", ["agent_memory_migrate.py", *argv]),
                    mock.patch.object(migrate, "migration_lock", return_value=mock.MagicMock()),
                    mock.patch.object(
                        migrate,
                        "publish_ready_preflight",
                        return_value={"ok": True, "status": "ready"},
                    ) as publish,
                    mock.patch("builtins.print"),
                ):
                    self.assertEqual(migrate.main(), 0)
                    publish.assert_called_once_with(
                        no_host_hooks=False,
                        required_hosts=expected,
                    )

    def test_publish_ready_host_attestation_is_immediately_doctor_compatible(self) -> None:
        codex = self.root / ".codex"
        codex.mkdir()
        codex_command = automation.canonical_hook_command(
            self.python,
            self.runtime,
            automation.codex_stop_hook_spec(),
        )
        (codex / "hooks.json").write_text(
            json.dumps({"hooks": {"Stop": [{"hooks": [self.entry(codex_command)]}]}}),
            encoding="utf-8",
        )
        (codex / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")

        claude = self.root / ".claude"
        claude.mkdir()
        claude_hooks: dict[str, object] = {}
        for event, spec in automation.claude_hook_specs().items():
            command = automation.canonical_hook_command(self.python, self.runtime, spec)
            claude_hooks[event] = [{"hooks": [self.entry(command, spec.timeout)]}]
        (claude / "settings.json").write_text(
            json.dumps({"hooks": claude_hooks}),
            encoding="utf-8",
        )

        with (
            mock.patch.object(migrate.Path, "home", return_value=self.root),
            mock.patch.object(migrate, "RUNTIME_ROOT", self.runtime),
        ):
            published = migrate._host_hook_health(
                no_host_hooks=False,
                required_hosts=("codex", "claude", "codex"),
                runtime_python=self.python,
            )
        self.assertEqual(published["hosts"], ["claude", "codex"])

        transition = self.root / "runtime-transition.json"
        transition.write_text(
            json.dumps({
                "phase": "ready",
                "preflight_attestation": {"host_hooks": published},
            }),
            encoding="utf-8",
        )
        policy = doctor.attested_host_hook_policy(transition)
        self.assertTrue(policy["valid"], policy)
        self.assertEqual(policy["hosts"], ["claude", "codex"])

    def test_doctor_scans_default_host_files_for_legacy_wrapper_references(self) -> None:
        wrapper = self.root / "on-stop-memory.sh"
        wrapper.write_text(
            f"exec {self.runtime}/scripts/agent_memory_stop_hook.py --actor codex\n",
            encoding="utf-8",
        )
        codex = self.root / ".codex"
        codex.mkdir()
        (codex / "hooks.json").write_text(
            json.dumps({
                "hooks": {
                    "Stop": [{"hooks": [self.entry(str(wrapper))]}],
                }
            }),
            encoding="utf-8",
        )
        with (
            mock.patch.object(doctor.Path, "home", return_value=self.root),
            mock.patch.object(doctor, "HOST_CONFIG", {}),
            mock.patch.object(doctor, "REPO_ROOT", self.runtime),
            mock.patch.object(doctor, "PYTHON", self.python),
        ):
            references = doctor.legacy_hook_wrapper_references()
        self.assertEqual(references, [str(wrapper)])

    def test_doctor_reads_required_hosts_from_ready_attestation_without_host_paths(self) -> None:
        transition = self.root / "runtime-transition.json"
        transition.write_text(
            json.dumps({
                "phase": "ready",
                "preflight_attestation": {
                    "host_hooks": {
                        "policy": "required",
                        "verified": True,
                        # Runtime v2 initially preserved CLI order. Doctor must
                        # accept that unique historical representation.
                        "hosts": ["codex", "claude"],
                    },
                },
            }),
            encoding="utf-8",
        )
        policy = doctor.attested_host_hook_policy(transition)
        self.assertTrue(policy["available"])
        self.assertTrue(policy["valid"])
        self.assertEqual(policy["hosts"], ["claude", "codex"])

        invalid_host_policies = (
            {"policy": "required", "verified": True, "hosts": ["codex", "codex"]},
            {"policy": "required", "verified": True, "hosts": ["codex", "vendor"]},
            {"policy": "required", "verified": True},
        )
        for host_hooks in invalid_host_policies:
            with self.subTest(host_hooks=host_hooks):
                transition.write_text(
                    json.dumps({
                        "phase": "ready",
                        "preflight_attestation": {"host_hooks": host_hooks},
                    }),
                    encoding="utf-8",
                )
                invalid = doctor.attested_host_hook_policy(transition)
                self.assertFalse(invalid["valid"])
                self.assertEqual(
                    invalid["reason_code"],
                    "HOST_HOOK_ATTESTATION_INVALID",
                )

    def test_attested_required_host_does_not_override_explicit_managed_path(self) -> None:
        configured = self.root / "managed" / "codex-hooks.json"
        with mock.patch.object(
            doctor,
            "HOST_CONFIG",
            {"codex_hooks_json": str(configured)},
        ):
            selected = doctor.configured_or_required_host_path(
                "codex_hooks_json",
                host="codex",
                required_hosts={"codex"},
                default=self.root / ".codex" / "hooks.json",
            )
        self.assertEqual(selected, configured)

        with mock.patch.object(doctor, "HOST_CONFIG", {}):
            fallback = doctor.configured_or_required_host_path(
                "codex_hooks_json",
                host="codex",
                required_hosts={"codex"},
                default=self.root / ".codex" / "hooks.json",
            )
        self.assertEqual(fallback, self.root / ".codex" / "hooks.json")

    def test_doctor_rejects_cc_switch_database_symlink_like_installer(self) -> None:
        target = self.root / "cc-switch-real.db"
        target.write_bytes(b"not-opened-through-symlink")
        alias = self.root / "cc-switch.db"
        alias.symlink_to(target)
        ok, detail = doctor.cc_switch_hooks_match(alias, {})
        self.assertFalse(ok)
        self.assertEqual(detail["error"], "CC_SWITCH_DB_UNSAFE")

    def test_publish_ready_rejects_shell_invoked_legacy_wrapper_beside_canonical(self) -> None:
        wrapper = self.root / "legacy-stop-wrapper.sh"
        wrapper.write_text(
            f"exec {self.runtime}/scripts/agent_memory_stop_hook.py --actor codex\n",
            encoding="utf-8",
        )
        canonical = automation.canonical_hook_command(
            self.python,
            self.runtime,
            self.spec,
        )
        codex = self.root / ".codex"
        codex.mkdir()
        (codex / "hooks.json").write_text(
            json.dumps({
                "hooks": {
                    "Stop": [{"hooks": [
                        self.entry(canonical),
                        self.entry(f"/bin/bash {wrapper}"),
                    ]}],
                },
            }),
            encoding="utf-8",
        )
        (codex / "config.toml").write_text(
            "[features]\nhooks = true\n",
            encoding="utf-8",
        )
        with (
            mock.patch.object(migrate.Path, "home", return_value=self.root),
            mock.patch.object(migrate, "RUNTIME_ROOT", self.runtime),
        ):
            with self.assertRaisesRegex(ValueError, "CODEX_HOOKS_INVALID"):
                migrate._host_hook_health(
                    no_host_hooks=False,
                    required_hosts=("codex",),
                    runtime_python=self.python,
                )

    def launch_spec(self) -> automation.LaunchAgentSpec:
        return automation.LaunchAgentSpec(
            label="com.example.agent-memory-audit",
            plist_path=self.root / "audit.plist",
            runtime_root=self.runtime,
            runtime_python=self.python,
            stdout_path=self.runtime / "logs" / "audit-launchd.out.log",
            stderr_path=self.runtime / "logs" / "audit-launchd.err.log",
            working_directory=self.root,
        )

    def test_launchagent_is_sunday_1030_and_uses_managed_memoryctl(self) -> None:
        spec = self.launch_spec()
        payload = automation.launchagent_payload(spec)
        self.assertEqual(payload["StartCalendarInterval"], {"Weekday": 0, "Hour": 10, "Minute": 30})
        self.assertEqual(payload["ProgramArguments"], list(spec.program_arguments))
        self.assertEqual(
            automation.classify_launchagent_payload(payload, spec).kind,
            automation.CANONICAL,
        )
        legacy = dict(payload)
        legacy["ProgramArguments"] = [
            "/usr/bin/python3",
            str(self.runtime / "scripts" / "agent_memory_audit_autorun.py"),
            "--json",
        ]
        self.assertEqual(
            automation.classify_launchagent_payload(legacy, spec).kind,
            automation.LEGACY,
        )

    def test_launchctl_parser_checks_exact_arguments_runs_and_exit(self) -> None:
        spec = self.launch_spec()
        arguments = "\n".join(f"\t\t{item}" for item in spec.program_arguments)
        output = (
            f"gui/501/{spec.label} = {{\n"
            "\tstate = not running\n"
            f"\tprogram = {spec.program_arguments[0]}\n"
            "\targuments = {\n"
            f"{arguments}\n"
            "\t}\n"
            "\truns = 4\n"
            "\tlast exit code = 0\n"
            "\tenvironment = {\n\t\tSECRET_SHOULD_NOT_BE_RETURNED\n\t}\n"
            "}\n"
        )
        health = automation.launchctl_health(
            print_returncode=0,
            print_stdout=output,
            spec=spec,
        )
        self.assertTrue(health["healthy"])
        self.assertEqual(health["runs"], 4)
        self.assertNotIn("SECRET", json.dumps(health))

        drifted = output.replace(
            f"program = {spec.program_arguments[0]}",
            "program = /usr/bin/python3",
        )
        drifted_health = automation.launchctl_health(
            print_returncode=0,
            print_stdout=drifted,
            spec=spec,
        )
        self.assertFalse(drifted_health["healthy"])
        self.assertFalse(drifted_health["program_exact"])

    def test_shared_scheduler_health_requires_a_recent_successful_report(self) -> None:
        spec = self.launch_spec()
        spec.plist_path.parent.mkdir(parents=True, exist_ok=True)
        spec.plist_path.write_bytes(automation.launchagent_bytes(spec))
        arguments = "\n".join(f"\t\t{item}" for item in spec.program_arguments)
        launchctl = (
            f"\tprogram = {spec.program_arguments[0]}\n"
            "\targuments = {\n"
            f"{arguments}\n"
            "\t}\n"
            "\truns = 1\n"
            "\tlast exit code = 0\n"
        )
        report = self.root / "latest-audit.json"
        report.write_text(
            '{"time":"2026-08-24T00:00:00+00:00","status":"error","ok":false}',
            encoding="utf-8",
        )
        health = automation.audit_scheduler_health(
            spec,
            print_returncode=0,
            print_stdout=launchctl,
            success_report_path=report,
            now=dt.datetime(2026, 8, 24, 1, tzinfo=dt.timezone.utc),
        )
        self.assertFalse(health["healthy"])
        self.assertTrue(health["launchctl"]["healthy"])
        self.assertFalse(health["success_report"]["healthy"])
        self.assertEqual(
            health["success_report"]["reason_code"],
            "AUDIT_REPORT_NOT_SUCCESSFUL",
        )

    def test_scheduler_inventory_rejects_duplicate_or_legacy_route(self) -> None:
        spec = self.launch_spec()
        directory = spec.plist_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        spec.plist_path.write_bytes(automation.launchagent_bytes(spec))
        duplicate = directory / "second-audit.plist"
        duplicate.write_bytes(automation.launchagent_bytes(spec))
        inventory = automation.discover_audit_launchagents(directory, spec)
        self.assertFalse(inventory["healthy"])
        self.assertEqual(inventory["canonical_count"], 2)

        duplicate_payload = automation.launchagent_payload(spec)
        duplicate_payload["Label"] = "com.example.second-agent-memory-audit"
        duplicate_payload["ProgramArguments"] = [
            "/usr/bin/python3",
            str(self.runtime / "scripts" / "agent_memory_audit_autorun.py"),
        ]
        duplicate.write_bytes(__import__("plistlib").dumps(duplicate_payload))
        inventory = automation.discover_audit_launchagents(directory, spec)
        self.assertFalse(inventory["healthy"])
        self.assertEqual(inventory["canonical_count"], 1)
        self.assertEqual(inventory["legacy_count"], 1)

    def test_scheduler_inventory_detects_generic_wrapper_and_custom_directory(self) -> None:
        spec = self.launch_spec()
        canonical_directory = self.root / "Library" / "LaunchAgents"
        canonical_directory.mkdir(parents=True)
        canonical_path = canonical_directory / "managed.plist"
        custom_spec = automation.LaunchAgentSpec(
            **{**spec.__dict__, "plist_path": canonical_path}
        )
        canonical_path.write_bytes(automation.launchagent_bytes(custom_spec))
        wrapper = self.root / "weekly-maintenance"
        wrapper.write_text(
            "#!/bin/sh\nexec memoryctl --actor human audit-autorun --reason launchd --json\n",
            encoding="utf-8",
        )
        legacy_payload = {
            "Label": "com.example.unrelated-name",
            "ProgramArguments": ["/bin/sh", str(wrapper)],
            "StartCalendarInterval": {"Weekday": 0, "Hour": 10, "Minute": 30},
        }
        (canonical_directory / "other.plist").write_bytes(
            __import__("plistlib").dumps(legacy_payload)
        )

        inventory = automation.discover_all_audit_launchagents(custom_spec)
        self.assertFalse(inventory["healthy"])
        self.assertEqual(inventory["canonical_count"], 1)
        self.assertEqual(inventory["ambiguous_count"], 1)

        (canonical_directory / "other.plist").write_bytes(
            __import__("plistlib").dumps({
                **legacy_payload,
                "ProgramArguments": [
                    "/bin/sh",
                    "-c",
                    f"{wrapper} --weekly",
                ],
            })
        )
        shell_inventory = automation.discover_all_audit_launchagents(custom_spec)
        self.assertFalse(shell_inventory["healthy"])
        self.assertEqual(shell_inventory["canonical_count"], 1)
        self.assertEqual(shell_inventory["ambiguous_count"], 1)

    @unittest.skipIf(os.name == "nt", "POSIX LaunchAgent symlink classification")
    def test_scheduler_inventory_detects_generic_symlink_wrapper(self) -> None:
        spec = self.launch_spec()
        directory = spec.plist_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        spec.plist_path.write_bytes(automation.launchagent_bytes(spec))
        target = self.root / "weekly-target"
        target.write_text(
            "#!/bin/sh\nexec memoryctl --actor human audit-autorun --reason launchd\n",
            encoding="utf-8",
        )
        alias = self.root / "weekly-helper"
        alias.symlink_to(target)
        (directory / "unrelated-name.plist").write_bytes(
            __import__("plistlib").dumps({
                "Label": "com.example.unrelated-name",
                "ProgramArguments": [str(alias), "--weekly"],
            })
        )

        inventory = automation.discover_all_audit_launchagents(spec)
        self.assertFalse(inventory["healthy"])
        self.assertEqual(inventory["canonical_count"], 1)
        self.assertEqual(inventory["ambiguous_count"], 1)
        self.assertEqual(
            inventory["routes"][1]["reason_code"],
            "AUDIT_LAUNCHAGENT_WRAPPER_SYMLINK",
        )

    def test_scheduler_inventory_ignores_unrelated_empty_and_malformed_google_plists(self) -> None:
        spec = self.launch_spec()
        directory = spec.plist_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        spec.plist_path.write_bytes(automation.launchagent_bytes(spec))
        plistlib = __import__("plistlib")
        (directory / "com.google.GoogleUpdater.wake.plist").write_bytes(
            plistlib.dumps({})
        )
        (directory / "com.google.keystone.xpcservice.plist").write_bytes(
            plistlib.dumps({"Label": "com.google.keystone.xpcservice"})
        )
        (directory / "com.google.malformed.plist").write_bytes(b"not a plist")

        inventory = automation.discover_all_audit_launchagents(spec)
        self.assertTrue(inventory["healthy"], inventory)
        self.assertEqual(inventory["canonical_count"], 1)
        self.assertEqual(inventory["legacy_count"], 0)
        self.assertEqual(inventory["ambiguous_count"], 0)
        self.assertEqual(len(inventory["routes"]), 1)

    def test_publish_ready_reuses_shared_inventory_for_unrelated_plists(self) -> None:
        label = "com.example.agent-memory-audit"
        directory = self.root / "Library" / "LaunchAgents"
        directory.mkdir(parents=True, exist_ok=True)
        plist_path = directory / f"{label}.plist"
        spec = automation.LaunchAgentSpec(
            label=label,
            plist_path=plist_path,
            runtime_root=self.runtime,
            runtime_python=self.python,
            stdout_path=self.runtime / "logs" / "audit-launchd.out.log",
            stderr_path=self.runtime / "logs" / "audit-launchd.err.log",
            working_directory=self.root,
        )
        plist_path.write_bytes(automation.launchagent_bytes(spec))
        (directory / "com.google.empty.plist").write_bytes(
            __import__("plistlib").dumps({})
        )
        with (
            mock.patch.object(migrate.sys, "platform", "darwin"),
            mock.patch.object(migrate.Path, "home", return_value=self.root),
            mock.patch.object(migrate, "RUNTIME_ROOT", self.runtime),
        ):
            result = migrate._publish_scheduler_health(
                {
                    "audit_launchagent_label": label,
                    "audit_launchagent": str(plist_path),
                    "python": str(self.python),
                }
            )
        self.assertTrue(result["healthy"])
        self.assertTrue(result["scheduler_inventory"]["healthy"])
        self.assertEqual(result["route_counts"]["ambiguous"], 0)

        alias = directory / "configured-alias.plist"
        alias.symlink_to(plist_path)
        with (
            mock.patch.object(migrate.sys, "platform", "darwin"),
            mock.patch.object(migrate.Path, "home", return_value=self.root),
            mock.patch.object(migrate, "RUNTIME_ROOT", self.runtime),
        ):
            with self.assertRaisesRegex(ValueError, "AUDIT_SCHEDULER_INVALID"):
                migrate._publish_scheduler_health(
                    {
                        "audit_launchagent_label": label,
                        "audit_launchagent": str(alias),
                        "python": str(self.python),
                    }
                )

    def test_report_freshness_uses_explicit_timestamp(self) -> None:
        report = self.root / "report.json"
        report.write_text('{"time":"2026-08-24T00:00:00+00:00"}\n', encoding="utf-8")
        current = dt.datetime(2026, 8, 25, tzinfo=dt.timezone.utc)
        self.assertTrue(automation.json_report_freshness(report, now=current)["fresh"])
        stale = dt.datetime(2026, 9, 5, tzinfo=dt.timezone.utc)
        self.assertFalse(automation.json_report_freshness(report, now=stale)["fresh"])

    def test_doctor_checks_default_scheduler_target_when_host_config_is_missing(self) -> None:
        with (
            mock.patch.object(doctor.sys, "platform", "darwin"),
            mock.patch.object(
                doctor,
                "run",
                return_value={"returncode": 113, "stdout": "", "ok": False},
            ),
        ):
            final = doctor.audit_launchagent_doctor_check(
                host_config={},
                runtime_root=self.runtime,
                runtime_python=self.python,
                home=self.root,
            )
            preflight = doctor.audit_launchagent_doctor_check(
                allow_content_migration_bootstrap=True,
                host_config={},
                runtime_root=self.runtime,
                runtime_python=self.python,
                home=self.root,
            )

        self.assertIsNotNone(final)
        self.assertIsNotNone(preflight)
        assert final is not None
        assert preflight is not None
        self.assertEqual(final["status"], "fail")
        self.assertEqual(preflight["status"], "warn")
        self.assertFalse(final["detail"]["configuration_complete"])
        self.assertEqual(
            final["detail"]["configuration_issues"],
            [
                "AUDIT_LAUNCHAGENT_LABEL_CONFIG_MISSING",
                "AUDIT_LAUNCHAGENT_PATH_CONFIG_MISSING",
            ],
        )
        self.assertEqual(
            final["detail"]["plist_path"],
            str(
                self.root
                / "Library"
                / "LaunchAgents"
                / f"{automation.DEFAULT_AUDIT_LAUNCHAGENT_LABEL}.plist"
            ),
        )

    def test_doctor_accepts_only_explicit_canonical_scheduler_with_exit_zero(self) -> None:
        spec = self.launch_spec()
        spec.plist_path.parent.mkdir(parents=True, exist_ok=True)
        spec.plist_path.write_bytes(automation.launchagent_bytes(spec))
        audit_report = self.root / "latest-audit.json"
        audit_report.write_text(
            json.dumps(
                {
                    "time": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "status": "ran",
                    "ok": True,
                }
            ),
            encoding="utf-8",
        )
        arguments = "\n".join(f"\t\t{item}" for item in spec.program_arguments)
        launchctl = (
            f"gui/501/{spec.label} = {{\n"
            f"\tprogram = {spec.program_arguments[0]}\n"
            "\targuments = {\n"
            f"{arguments}\n"
            "\t}\n"
            "\truns = 2\n"
            "\tlast exit code = 0\n"
            "}\n"
        )
        with (
            mock.patch.object(doctor.sys, "platform", "darwin"),
            mock.patch.object(
                doctor,
                "run",
                return_value={"returncode": 0, "stdout": launchctl, "ok": True},
            ),
            mock.patch.object(doctor, "AUDIT_REPORT", audit_report),
        ):
            result = doctor.audit_launchagent_doctor_check(
                host_config={
                    "audit_launchagent_label": spec.label,
                    "audit_launchagent": str(spec.plist_path),
                },
                runtime_root=self.runtime,
                runtime_python=self.python,
                home=self.root,
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["detail"]["configuration_complete"])
        self.assertEqual(result["detail"]["launchctl"]["last_exit_code"], 0)
        self.assertTrue(result["detail"]["success_report"]["healthy"])

        duplicate = spec.plist_path.with_name("duplicate-audit.plist")
        duplicate.write_bytes(automation.launchagent_bytes(spec))
        with (
            mock.patch.object(doctor.sys, "platform", "darwin"),
            mock.patch.object(
                doctor,
                "run",
                return_value={"returncode": 0, "stdout": launchctl, "ok": True},
            ),
            mock.patch.object(doctor, "AUDIT_REPORT", audit_report),
        ):
            duplicate_result = doctor.audit_launchagent_doctor_check(
                host_config={
                    "audit_launchagent_label": spec.label,
                    "audit_launchagent": str(spec.plist_path),
                },
                runtime_root=self.runtime,
                runtime_python=self.python,
                home=self.root,
            )
        assert duplicate_result is not None
        self.assertEqual(duplicate_result["status"], "fail")
        self.assertEqual(
            duplicate_result["detail"]["scheduler_inventory"]["canonical_count"],
            2,
        )

    def test_doctor_preserves_venv_launcher_lexically_and_rejects_plist_symlink(self) -> None:
        real_python = self.root / "base-python"
        real_python.write_text("python\n", encoding="utf-8")
        venv_python = self.runtime / ".venv" / "bin" / "python-link"
        venv_python.symlink_to(real_python)
        spec = automation.LaunchAgentSpec(
            **{
                **self.launch_spec().__dict__,
                "runtime_python": venv_python,
            }
        )
        spec.plist_path.parent.mkdir(parents=True, exist_ok=True)
        spec.plist_path.write_bytes(automation.launchagent_bytes(spec))
        audit_report = self.root / "latest-audit-symlink-python.json"
        audit_report.write_text(
            json.dumps({
                "time": dt.datetime.now(dt.timezone.utc).isoformat(),
                "status": "ran",
                "ok": True,
            }),
            encoding="utf-8",
        )
        arguments = "\n".join(f"\t\t{item}" for item in spec.program_arguments)
        launchctl = (
            f"gui/501/{spec.label} = {{\n"
            f"\tprogram = {spec.program_arguments[0]}\n"
            "\targuments = {\n"
            f"{arguments}\n"
            "\t}\n"
            "\truns = 1\n"
            "\tlast exit code = 0\n"
            "}\n"
        )
        with (
            mock.patch.object(doctor.sys, "platform", "darwin"),
            mock.patch.object(
                doctor,
                "run",
                return_value={"returncode": 0, "stdout": launchctl, "ok": True},
            ),
            mock.patch.object(doctor, "AUDIT_REPORT", audit_report),
        ):
            healthy = doctor.audit_launchagent_doctor_check(
                host_config={
                    "audit_launchagent_label": spec.label,
                    "audit_launchagent": str(spec.plist_path),
                },
                runtime_root=self.runtime,
                runtime_python=venv_python,
                home=self.root,
            )
        assert healthy is not None
        self.assertEqual(healthy["status"], "pass")
        self.assertTrue(healthy["detail"]["launchctl"]["program_exact"])

        alias = spec.plist_path.with_name("audit-alias.plist")
        alias.symlink_to(spec.plist_path)
        with (
            mock.patch.object(doctor.sys, "platform", "darwin"),
            mock.patch.object(
                doctor,
                "run",
                return_value={"returncode": 0, "stdout": launchctl, "ok": True},
            ),
            mock.patch.object(doctor, "AUDIT_REPORT", audit_report),
        ):
            unsafe = doctor.audit_launchagent_doctor_check(
                host_config={
                    "audit_launchagent_label": spec.label,
                    "audit_launchagent": str(alias),
                },
                runtime_root=self.runtime,
                runtime_python=venv_python,
                home=self.root,
            )
        assert unsafe is not None
        self.assertEqual(unsafe["status"], "fail")
        self.assertEqual(
            unsafe["detail"]["classification"]["kind"],
            automation.AMBIGUOUS,
        )


if __name__ == "__main__":
    unittest.main()
