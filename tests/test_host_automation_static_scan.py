from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_check as CHECK


class HostAutomationStaticScanTests(unittest.TestCase):
    def test_windows_installer_uses_exact_memoryctl_route_and_shared_verifier(self) -> None:
        installer = (SCRIPTS / "install-codex-hook.ps1").read_text(encoding="utf-8")
        self.assertIn(
            "-I -S \"{1}\" --actor codex stop-hook --protocol codex "
            "--event stop-hook{2} --timeout 300",
            installer,
        )
        self.assertIn("$memoryctl = Join-Path $RuntimeRoot 'scripts\\memoryctl'", installer)
        self.assertNotIn("-ExecutionPolicy Bypass -File", installer)
        self.assertIn("agent_memory_host_automation.py", installer)
        self.assertIn("'verify-codex-hook'", installer)
        self.assertIn("if ($AutoCloseout) { $verificationArgs += '--auto-closeout' }", installer)
        self.assertIn("if ($AutoCloseout) { 320 } else { 20 }", installer)
        self.assertIn("'classify-codex-hook-entry'", installer)
        self.assertIn("switch ($classification.kind)", installer)
        self.assertIn("'unrelated' {", installer)
        self.assertIn("throw 'CODEX_HOOK_CLASSIFIER_FAILED'", installer)
        self.assertIn("throw 'CODEX_HOOK_UNMANAGED_AMBIGUOUS'", installer)
        self.assertIn("$classification.agent_memory_route", installer)
        self.assertIn(
            "'ambiguous' {\n                if (-not $classification.agent_memory_route)",
            installer,
        )
        self.assertLess(
            installer.index("throw 'CODEX_HOOK_UNMANAGED_AMBIGUOUS'"),
            installer.index("Write-AtomicWithBackup $HooksPath"),
        )
        self.assertIn(
            "$utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)",
            installer,
        )
        self.assertIn("$hooksText = $utf8Strict.GetString($hooksBefore)", installer)
        self.assertNotIn("Get-Content -Raw -LiteralPath $HooksPath", installer)
        self.assertIn("throw 'CODEX_HOOK_EVENT_DISABLED'", installer)
        self.assertLess(
            installer.index("throw 'CODEX_HOOK_EVENT_DISABLED'"),
            installer.index("Write-AtomicWithBackup $HooksPath"),
        )
        self.assertIn("$canonicalGroup.hooks = @($canonicalGroup.hooks) + @($canonicalHook)", installer)
        self.assertNotIn("agent_memory_stop_hook.py", installer)
        failures = CHECK.check_host_automation_examples(SCRIPTS.parent)
        self.assertFalse(
            any("adapter=scripts/install-codex-hook.ps1" in item for item in failures),
            failures,
        )

    def test_no_private_windows_hook_classifier_can_drift_from_shared_rule(self) -> None:
        migrate_source = (SCRIPTS / "agent_memory_migrate.py").read_text(encoding="utf-8")
        doctor_source = (SCRIPTS / "agent_memory_doctor.py").read_text(encoding="utf-8")
        self.assertNotIn("def _windows_wrapper_matches", migrate_source)
        self.assertNotIn('"stop-hook.ps1" in hooks_text', doctor_source)
        self.assertIn("spec=codex_stop_hook_spec()", migrate_source)
        self.assertIn("spec=codex_stop_hook_spec()", doctor_source)

    def test_rejects_low_level_python_in_copyable_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            docs = root / "docs"
            docs.mkdir()
            (docs / "automation.md").write_text(
                "```bash\npython3 scripts/agent_memory_stop_hook.py --actor codex\n```\n",
                encoding="utf-8",
            )
            failures = CHECK.check_host_automation_examples(root)
            self.assertTrue(any("HOST_AUTOMATION_BYPASS" in item for item in failures))

    def test_rejects_low_level_host_route_in_root_readme(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            (root / "README.md").write_text(
                "```bash\npython3 scripts/agent_memory_audit_autorun.py --reason manual\n```\n",
                encoding="utf-8",
            )
            failures = CHECK.check_host_automation_examples(root)
            self.assertTrue(any("example=README.md" in item for item in failures))

    def test_rejects_any_direct_python_adapter_in_automation_guide(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            docs = root / "docs"
            docs.mkdir()
            (docs / "automation.md").write_text(
                "```bash\npython3 scripts/agent_memory_closeout.py --commit\n```\n",
                encoding="utf-8",
            )
            failures = CHECK.check_host_automation_examples(root)
            self.assertTrue(any("example=docs/automation.md" in item for item in failures))

    def test_rejects_obsolete_codex_claim_file_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            (root / "README.zh-CN.md").write_text(
                "memoryctl --actor codex claim --file 项目/example.md\n",
                encoding="utf-8",
            )
            failures = CHECK.check_host_automation_examples(root)
            self.assertTrue(any("OBSOLETE_CLAIM_GUIDANCE" in item for item in failures))

    def test_accepts_managed_memoryctl_route(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            docs = root / "docs"
            scripts = root / "scripts"
            docs.mkdir()
            scripts.mkdir()
            (docs / "automation.md").write_text(
                "```bash\n/runtime/.venv/bin/python -I -S /runtime/scripts/memoryctl "
                "--actor codex stop-hook\n```\n",
                encoding="utf-8",
            )
            (scripts / "stop-hook.ps1").write_text(
                "$arguments = @('-I', '-S', $memoryctl, '--actor', $Actor, 'stop-hook')\n",
                encoding="utf-8",
            )
            self.assertEqual(CHECK.check_host_automation_examples(root), [])

    def test_rejects_low_level_target_in_production_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "audit-task.ps1").write_text(
                "$target = 'agent_memory_audit_autorun.py'\n",
                encoding="utf-8",
            )
            failures = CHECK.check_host_automation_examples(root)
            self.assertTrue(any("adapter=scripts/audit-task.ps1" in item for item in failures))

    def test_rejects_weekly_audit_spawned_from_stop_hook(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "agent_memory_stop_hook.py").write_text(
                "target = 'agent_memory_audit_autorun.py'\n",
                encoding="utf-8",
            )
            failures = CHECK.check_host_automation_examples(root)
            self.assertTrue(
                any("adapter=scripts/agent_memory_stop_hook.py" in item for item in failures)
            )


if __name__ == "__main__":
    unittest.main()
