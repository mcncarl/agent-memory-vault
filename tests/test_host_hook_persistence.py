from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import install_host_hooks as hooks
import agent_memory_doctor as doctor


def dump(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def commands(payload: dict[str, object], event: str) -> list[str]:
    result: list[str] = []
    for group in payload.get(event, []):
        if not isinstance(group, dict):
            continue
        for entry in group.get("hooks", []):
            if isinstance(entry, dict) and isinstance(entry.get("command"), str):
                result.append(entry["command"])
    return result


class HostHookPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.python = Path("/private/runtime/.venv/bin/python")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_cc_switch_db(self, *, include_common: bool = True) -> Path:
        path = self.root / "cc-switch.db"
        with sqlite3.connect(path) as connection:
            connection.executescript(
                """
                CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE proxy_live_backup (
                    app_type TEXT PRIMARY KEY,
                    original_config TEXT NOT NULL,
                    backed_up_at TEXT NOT NULL
                );
                CREATE TABLE providers (
                    id TEXT NOT NULL,
                    app_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    settings_config TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    PRIMARY KEY (id, app_type)
                );
                """
            )
            stale_hooks = {
                "SessionStart": [{"hooks": [{
                    "type": "command",
                    "command": (
                        "/usr/bin/python3 /private/runtime/scripts/"
                        "agent_memory_session_hook.py --actor claude"
                    ),
                    "timeout": 10,
                }]}],
                "Stop": [{"hooks": [
                    {"type": "command", "command": "provider-notify"},
                    {
                        "type": "command",
                        "command": (
                            "/usr/bin/python3 /private/runtime/scripts/"
                            "agent_memory_stop_hook.py --actor claude --protocol claude "
                            "--event stop-hook --auto-closeout --timeout 300"
                        ),
                        "timeout": 320,
                    },
                ]}],
                "SessionEnd": [{"hooks": [{
                    "type": "command",
                    "command": (
                        "/usr/bin/python3 /private/runtime/scripts/"
                        "agent_memory_stop_hook.py --actor claude --protocol claude "
                        "--event session-end --non-blocking --auto-closeout --timeout 55"
                    ),
                    "timeout": 60,
                }]}],
            }
            if include_common:
                connection.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)",
                    (
                        "common_config_claude",
                        json.dumps({
                            "env": {"KEEP_COMMON": "yes"},
                            "hooks": {
                                "Notification": [{"hooks": [{
                                    "type": "command",
                                    "command": "common-notify",
                                }]}],
                            },
                        }, ensure_ascii=False),
                    ),
                )
            connection.execute(
                "INSERT INTO proxy_live_backup VALUES (?, ?, ?)",
                (
                    "claude",
                    json.dumps({
                        "permissions": {"allow": ["Read"]},
                        "hooks": {
                            "Stop": [{"matcher": "tool", "hooks": [{
                                "type": "command",
                                "command": "backup-notify",
                            }]}],
                        },
                    }, ensure_ascii=False),
                    "2026-08-12T00:00:00Z",
                ),
            )
            connection.execute(
                "INSERT INTO providers VALUES (?, ?, ?, ?, ?)",
                (
                    "provider-with-hooks",
                    "claude",
                    "Provider A",
                    json.dumps({
                        "endpoint": "https://example.invalid",
                        "hooks": stale_hooks,
                    }, ensure_ascii=False),
                    "keep provider note",
                ),
            )
            connection.execute(
                "INSERT INTO providers VALUES (?, ?, ?, ?, ?)",
                (
                    "provider-without-hooks",
                    "claude",
                    "Provider B",
                    json.dumps({"model": "example-model"}, ensure_ascii=False),
                    "keep second note",
                ),
            )
            connection.execute(
                "INSERT INTO providers VALUES (?, ?, ?, ?, ?)",
                (
                    "other-app-provider",
                    "codex",
                    "Provider C",
                    json.dumps({"hooks": {"Stop": []}}, ensure_ascii=False),
                    "untouched other app",
                ),
            )
        return path

    def build_expected_hooks(
        self,
        database: Path,
    ) -> tuple[hooks.CcSwitchState, dict[str, object]]:
        settings = self.root / "settings.json"
        fragment = self.root / "claude-hooks.json"
        dump(settings, {
            "env": {"KEEP_SETTINGS": "yes"},
            "hooks": {
                "Stop": [{"hooks": [{
                    "type": "command",
                    "command": "settings-notify",
                }]}],
            },
        })
        dump(fragment, {
            "Notification": [{"hooks": [{
                "type": "command",
                "command": "fragment-notify",
            }]}],
        })
        state = hooks.load_cc_switch_state(database)
        settings_bytes, fragment_bytes, expected, _operations = (
            hooks.claude_persistence_payloads(
                settings,
                fragment,
                self.python,
                additional_global_hooks=hooks.cc_switch_global_hook_sources(state),
            )
        )
        settings_payload = json.loads(settings_bytes)
        fragment_payload = json.loads(fragment_bytes)
        self.assertEqual(settings_payload["hooks"], fragment_payload)
        self.assertEqual(settings_payload["env"], {"KEEP_SETTINGS": "yes"})
        self.assertIn("settings-notify", commands(fragment_payload, "Stop"))
        self.assertIn("fragment-notify", commands(fragment_payload, "Notification"))
        if state.common_config is not None:
            self.assertIn("common-notify", commands(fragment_payload, "Notification"))
        self.assertIn("backup-notify", commands(fragment_payload, "Stop"))
        for event, script_name in (
            ("SessionStart", "agent_memory_session_hook.py"),
            ("Stop", "agent_memory_stop_hook.py"),
            ("SessionEnd", "agent_memory_stop_hook.py"),
        ):
            managed = [
                command
                for command in commands(fragment_payload, event)
                if hooks._managed_event_route(command, script_name=script_name)
            ]
            self.assertEqual(len(managed), 1, (event, managed))
            self.assertIn("memoryctl", managed[0])
        return state, expected

    def persistence_snapshot(self, database: Path) -> tuple[object, ...]:
        with sqlite3.connect(database) as connection:
            common = connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("common_config_claude",),
            ).fetchone()
            backups = tuple(connection.execute(
                "SELECT app_type, original_config FROM proxy_live_backup ORDER BY app_type"
            ).fetchall())
            providers = tuple(connection.execute(
                "SELECT id, app_type, settings_config FROM providers ORDER BY id, app_type"
            ).fetchall())
        return common, backups, providers

    def run_apply(self, database: Path, backup_dir: Path) -> dict[str, object]:
        stdout = io.StringIO()
        argv = [
            "install_host_hooks.py",
            "--host", "claude",
            "--claude-settings", str(self.root / "settings.json"),
            "--claude-hooks-fragment", str(self.root / "claude-hooks.json"),
            "--cc-switch-db", str(database),
            "--backup-dir", str(backup_dir),
            "--apply",
            "--json",
        ]
        with (
            mock.patch.object(hooks, "configured_python", return_value=self.python),
            mock.patch.object(sys, "argv", argv),
            contextlib.redirect_stdout(stdout),
        ):
            return_code = hooks.main()
        report = json.loads(stdout.getvalue())
        report["return_code"] = return_code
        return report

    def test_shared_fragment_unions_unrelated_hooks_and_canonicalizes_routes(self) -> None:
        database = self.create_cc_switch_db()
        self.build_expected_hooks(database)

    def test_codex_payload_removes_legacy_wrapper_reference_but_keeps_notifications(self) -> None:
        wrapper = self.root / "on-stop-memory.sh"
        wrapper.write_text(
            "#!/bin/sh\nexec /usr/bin/python3 /private/runtime/scripts/"
            "agent_memory_stop_hook.py --actor codex --protocol codex "
            "--auto-closeout --timeout 300\n",
            encoding="utf-8",
        )
        path = self.root / "hooks.json"
        dump(path, {
            "hooks": {
                "Stop": [{"hooks": [
                    {"type": "command", "command": str(wrapper), "timeout": 320},
                    {"type": "command", "command": "notify-desktop", "timeout": 10},
                ]}]
            }
        })
        content, _operations = hooks.codex_payload(path, self.python)
        payload = json.loads(content)
        stop_commands = commands(payload["hooks"], "Stop")
        self.assertNotIn(str(wrapper), stop_commands)
        self.assertIn("notify-desktop", stop_commands)
        self.assertEqual(
            len([item for item in stop_commands if "memoryctl" in item and "stop-hook" in item]),
            1,
        )

    def test_codex_payload_removes_shell_invoked_legacy_wrapper(self) -> None:
        wrapper = self.root / "on-stop-memory.sh"
        wrapper.write_text(
            "#!/bin/sh\nexec /usr/bin/python3 /private/runtime/scripts/"
            "agent_memory_stop_hook.py --actor codex\n",
            encoding="utf-8",
        )
        path = self.root / "hooks-shell-wrapper.json"
        dump(path, {
            "hooks": {
                "Stop": [{"hooks": [
                    {
                        "type": "command",
                        "command": f"/bin/bash {wrapper}",
                        "timeout": 320,
                    },
                ]}],
            },
        })
        content, _operations = hooks.codex_payload(path, self.python)
        stop_commands = commands(json.loads(content)["hooks"], "Stop")
        self.assertNotIn(f"/bin/bash {wrapper}", stop_commands)
        self.assertEqual(
            len([item for item in stop_commands if "memoryctl" in item and "stop-hook" in item]),
            1,
        )

    def test_merge_event_moves_managed_route_out_of_matcher_scope(self) -> None:
        old_managed = {
            "type": "command",
            "command": (
                "/usr/bin/python3 /private/runtime/scripts/"
                "agent_memory_stop_hook.py --actor codex"
            ),
            "timeout": 320,
        }
        replacement = {
            "type": "command",
            "command": "canonical-memoryctl-stop",
            "timeout": 320,
        }
        payload = {
            "Stop": [{
                "matcher": "tool",
                "hooks": [old_managed, {"type": "command", "command": "notify"}],
            }]
        }
        result = hooks.merge_event(
            payload,
            "Stop",
            script_name="agent_memory_stop_hook.py",
            entry=replacement,
        )
        self.assertEqual(result, "added")
        self.assertEqual(payload["Stop"][0]["hooks"], [{"type": "command", "command": "notify"}])
        self.assertEqual(payload["Stop"][-1], {"hooks": [replacement]})

    def test_doctor_rejects_provider_hook_shape_that_installer_rejects(self) -> None:
        database = self.create_cc_switch_db()
        with sqlite3.connect(database) as connection:
            row = connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("provider-with-hooks", "claude"),
            ).fetchone()
            payload = json.loads(str(row[0]))
            payload["hooks"] = []
            connection.execute(
                "UPDATE providers SET settings_config = ? WHERE id = ? AND app_type = ?",
                (
                    json.dumps(payload),
                    "provider-with-hooks",
                    "claude",
                ),
            )
            connection.commit()
        with mock.patch.object(
            doctor,
            "claude_hook_semantics",
            return_value=(True, {"healthy": True}),
        ):
            ok, detail = doctor.cc_switch_hooks_match(database, {"Stop": []})
        self.assertFalse(ok)
        self.assertFalse(detail["provider_payloads_ok"])

    def test_cli_preview_reports_all_persistence_targets_without_mutation(self) -> None:
        database = self.create_cc_switch_db()
        self.build_expected_hooks(database)
        settings = self.root / "settings.json"
        fragment = self.root / "claude-hooks.json"
        settings_before = settings.read_bytes()
        fragment_before = fragment.read_bytes()
        with sqlite3.connect(database) as connection:
            common_before = connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("common_config_claude",),
            ).fetchone()[0]
        stdout = io.StringIO()
        argv = [
            "install_host_hooks.py",
            "--host", "claude",
            "--claude-settings", str(settings),
            "--claude-hooks-fragment", str(fragment),
            "--cc-switch-db", str(database),
            "--json",
        ]
        with (
            mock.patch.object(hooks, "configured_python", return_value=self.python),
            mock.patch.object(sys, "argv", argv),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(hooks.main(), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["status"], "preview")
        self.assertTrue(report["claude_persistence"]["cc_switch"]["changed"])
        self.assertEqual(report["backups"], [])
        self.assertEqual(settings.read_bytes(), settings_before)
        self.assertEqual(fragment.read_bytes(), fragment_before)
        with sqlite3.connect(database) as connection:
            self.assertEqual(connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("common_config_claude",),
            ).fetchone()[0], common_before)

    def test_first_file_failure_compensates_committed_database(self) -> None:
        database = self.create_cc_switch_db()
        self.build_expected_hooks(database)
        settings = self.root / "settings.json"
        fragment = self.root / "claude-hooks.json"
        settings_before = settings.read_bytes()
        fragment_before = fragment.read_bytes()
        database_before = self.persistence_snapshot(database)
        with mock.patch.object(
            hooks,
            "atomic_write",
            side_effect=OSError("INJECTED_FIRST_FILE_FAILURE"),
        ):
            report = self.run_apply(database, self.root / "failure-one-backup")
        self.assertEqual(report["status"], "rolled_back")
        self.assertEqual(report["reason_code"], "INJECTED_FIRST_FILE_FAILURE")
        self.assertEqual(report["return_code"], 2)
        self.assertTrue(report["recovery"]["automatic_compensation_complete"])
        self.assertEqual(settings.read_bytes(), settings_before)
        self.assertEqual(fragment.read_bytes(), fragment_before)
        self.assertEqual(self.persistence_snapshot(database), database_before)
        journal = Path(report["transaction_journal"])
        self.assertTrue(journal.is_file())
        self.assertEqual(
            json.loads(journal.read_text(encoding="utf-8").splitlines()[-1])["event"],
            "rolled_back",
        )
        self.assertTrue(all(Path(item["path"]).is_file() for item in report["backups"]))

    def test_second_file_failure_compensates_first_file_and_database(self) -> None:
        database = self.create_cc_switch_db()
        self.build_expected_hooks(database)
        settings = self.root / "settings.json"
        fragment = self.root / "claude-hooks.json"
        settings_before = settings.read_bytes()
        fragment_before = fragment.read_bytes()
        database_before = self.persistence_snapshot(database)
        real_atomic_write = hooks.atomic_write
        call_count = 0

        def fail_second(
            path: Path,
            content: bytes,
            *,
            expected_before_sha256: str,
        ) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise OSError("INJECTED_SECOND_FILE_FAILURE")
            real_atomic_write(
                path,
                content,
                expected_before_sha256=expected_before_sha256,
            )

        with mock.patch.object(hooks, "atomic_write", side_effect=fail_second):
            report = self.run_apply(database, self.root / "failure-two-backup")
        self.assertEqual(report["status"], "rolled_back")
        self.assertEqual(report["reason_code"], "INJECTED_SECOND_FILE_FAILURE")
        self.assertEqual(call_count, 3)
        self.assertEqual(settings.read_bytes(), settings_before)
        self.assertEqual(fragment.read_bytes(), fragment_before)
        self.assertEqual(self.persistence_snapshot(database), database_before)

    def test_failure_immediately_after_database_commit_is_compensated(self) -> None:
        database = self.create_cc_switch_db()
        self.build_expected_hooks(database)
        settings = self.root / "settings.json"
        fragment = self.root / "claude-hooks.json"
        settings_before = settings.read_bytes()
        fragment_before = fragment.read_bytes()
        database_before = self.persistence_snapshot(database)
        real_append = hooks.append_transaction_event
        failed = False

        def fail_after_database(path: Path, event: dict[str, object]) -> None:
            nonlocal failed
            if event.get("event") == "database_applied" and not failed:
                failed = True
                raise OSError("INJECTED_POST_DATABASE_COMMIT_FAILURE")
            real_append(path, event)

        with mock.patch.object(
            hooks,
            "append_transaction_event",
            side_effect=fail_after_database,
        ):
            report = self.run_apply(database, self.root / "post-db-backup")
        self.assertTrue(failed)
        self.assertEqual(report["status"], "rolled_back")
        self.assertEqual(
            report["reason_code"],
            "INJECTED_POST_DATABASE_COMMIT_FAILURE",
        )
        self.assertEqual(settings.read_bytes(), settings_before)
        self.assertEqual(fragment.read_bytes(), fragment_before)
        self.assertEqual(self.persistence_snapshot(database), database_before)

    def test_compensation_cas_drift_returns_recovery_required(self) -> None:
        database = self.create_cc_switch_db()
        self.build_expected_hooks(database)
        settings = self.root / "settings.json"
        fragment = self.root / "claude-hooks.json"
        fragment_before = fragment.read_bytes()
        database_before = self.persistence_snapshot(database)
        real_atomic_write = hooks.atomic_write
        call_count = 0

        def fail_second_with_external_drift(
            path: Path,
            content: bytes,
            *,
            expected_before_sha256: str,
        ) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                settings.write_bytes(b"external concurrent change\n")
                raise OSError("INJECTED_SECOND_FILE_FAILURE")
            real_atomic_write(
                path,
                content,
                expected_before_sha256=expected_before_sha256,
            )

        with mock.patch.object(
            hooks,
            "atomic_write",
            side_effect=fail_second_with_external_drift,
        ):
            report = self.run_apply(database, self.root / "recovery-required-backup")
        self.assertEqual(report["status"], "recovery_required")
        self.assertEqual(report["reason_code"], "RECOVERY_REQUIRED")
        self.assertFalse(report["recovery"]["automatic_compensation_complete"])
        self.assertEqual(settings.read_bytes(), b"external concurrent change\n")
        self.assertEqual(fragment.read_bytes(), fragment_before)
        self.assertEqual(self.persistence_snapshot(database), database_before)
        self.assertTrue(Path(report["transaction_journal"]).is_file())
        self.assertTrue(all(Path(item["path"]).is_file() for item in report["backups"]))

    def test_cc_switch_apply_preserves_unrelated_fields_and_provider_hooks(self) -> None:
        database = self.create_cc_switch_db()
        state, expected = self.build_expected_hooks(database)
        with sqlite3.connect(database) as connection:
            provider_without_hooks_before = connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("provider-without-hooks", "claude"),
            ).fetchone()[0]
            other_app_before = connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("other-app-provider", "codex"),
            ).fetchone()[0]
            common_before = connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("common_config_claude",),
            ).fetchone()[0]

        plan = hooks.plan_cc_switch_updates(state, expected, self.python)
        self.assertEqual(plan.common_action, "updated")
        self.assertEqual(plan.provider_count, 2)
        self.assertEqual(plan.provider_hooks_count, 1)
        self.assertEqual(plan.provider_hooks_updated, 1)
        backup = hooks.exclusive_sqlite_backup(database, self.root / "backups")
        hooks.apply_cc_switch_plan(plan)

        with sqlite3.connect(database) as connection:
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            common = json.loads(connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("common_config_claude",),
            ).fetchone()[0])
            backup_config = json.loads(connection.execute(
                "SELECT original_config FROM proxy_live_backup WHERE app_type = ?",
                ("claude",),
            ).fetchone()[0])
            provider = json.loads(connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("provider-with-hooks", "claude"),
            ).fetchone()[0])
            self.assertEqual(common["env"], {"KEEP_COMMON": "yes"})
            self.assertEqual(common["hooks"], expected)
            self.assertEqual(backup_config["permissions"], {"allow": ["Read"]})
            self.assertEqual(backup_config["hooks"], expected)
            self.assertEqual(provider["endpoint"], "https://example.invalid")
            self.assertIn("provider-notify", commands(provider["hooks"], "Stop"))
            with mock.patch.object(doctor, "PYTHON", self.python):
                semantics_ok, detail = doctor.claude_hook_semantics(provider["hooks"])
            self.assertTrue(semantics_ok, detail)
            self.assertEqual(connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("provider-without-hooks", "claude"),
            ).fetchone()[0], provider_without_hooks_before)
            self.assertEqual(connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("other-app-provider", "codex"),
            ).fetchone()[0], other_app_before)
            self.assertEqual(connection.execute(
                "SELECT notes FROM providers WHERE id = ? AND app_type = ?",
                ("provider-with-hooks", "claude"),
            ).fetchone()[0], "keep provider note")

        with sqlite3.connect(backup["path"]) as connection:
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("common_config_claude",),
            ).fetchone()[0], common_before)

    def test_cc_switch_apply_fails_closed_on_row_level_cas_drift(self) -> None:
        database = self.create_cc_switch_db()
        state, expected = self.build_expected_hooks(database)
        plan = hooks.plan_cc_switch_updates(state, expected, self.python)
        common_before = state.common_config[0]
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE providers SET settings_config = ? WHERE id = ? AND app_type = ?",
                (
                    json.dumps({"externally_changed": True}),
                    "provider-with-hooks",
                    "claude",
                ),
            )
        with self.assertRaisesRegex(ValueError, "CC_SWITCH_CHANGED_BEFORE_REPLACE"):
            hooks.apply_cc_switch_plan(plan)
        with sqlite3.connect(database) as connection:
            self.assertEqual(connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("common_config_claude",),
            ).fetchone()[0], common_before)
            self.assertEqual(json.loads(connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("provider-with-hooks", "claude"),
            ).fetchone()[0]), {"externally_changed": True})

    def test_cc_switch_missing_common_config_is_added_without_touching_providers(self) -> None:
        database = self.create_cc_switch_db(include_common=False)
        state, expected = self.build_expected_hooks(database)
        with sqlite3.connect(database) as connection:
            provider_before = connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("provider-without-hooks", "claude"),
            ).fetchone()[0]
        plan = hooks.plan_cc_switch_updates(state, expected, self.python)
        self.assertEqual(plan.common_action, "added")
        hooks.apply_cc_switch_plan(plan)
        with sqlite3.connect(database) as connection:
            common = json.loads(connection.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("common_config_claude",),
            ).fetchone()[0])
            self.assertEqual(common["hooks"], expected)
            self.assertEqual(connection.execute(
                "SELECT settings_config FROM providers WHERE id = ? AND app_type = ?",
                ("provider-without-hooks", "claude"),
            ).fetchone()[0], provider_before)


if __name__ == "__main__":
    unittest.main()
