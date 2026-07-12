from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_audit_autorun as autorun


def args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "reason": "test",
        "min_interval_days": 7,
        "limit": 50,
        "stale_days": 120,
        "open_loop_threshold": 4,
        "timeout": 30,
        "doctor_timeout": 30,
        "skip_doctor": False,
        "notify": True,
        "notify_ok": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class AuditAutorunDoctorTests(unittest.TestCase):
    def test_due_audit_runs_doctor_and_notifies_on_health_warning(self) -> None:
        audit_result = {
            "ok": True,
            "returncode": 0,
            "stdout": json.dumps({"findings": []}),
            "stderr": "",
        }
        doctor_result = {
            "ok": True,
            "returncode": 0,
            "stdout": json.dumps(
                {"status": "warning", "summary": {"pass": 25, "warn": 1, "fail": 0}}
            ),
            "stderr": "",
        }
        with mock.patch.object(autorun, "run_command", side_effect=[audit_result, doctor_result]), mock.patch.object(
            autorun, "write_report"
        ), mock.patch.object(autorun, "write_doctor_report"), mock.patch.object(
            autorun, "append_run_log"
        ), mock.patch.object(autorun, "notify") as notify_mock:
            payload = autorun.run_audit(args(), None)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["doctor_status"], "warning")
        self.assertEqual(payload["doctor_summary"]["warn"], 1)
        notify_mock.assert_called_once()
        self.assertIn("Doctor=warning", notify_mock.call_args.args[1])

    def test_doctor_error_does_not_erase_successful_audit_timestamp(self) -> None:
        audit_result = {
            "ok": True,
            "returncode": 0,
            "stdout": json.dumps({"findings": []}),
            "stderr": "",
        }
        doctor_result = {
            "ok": False,
            "returncode": 2,
            "stdout": json.dumps(
                {"status": "error", "summary": {"pass": 20, "warn": 0, "fail": 1}}
            ),
            "stderr": "",
        }
        with mock.patch.object(autorun, "run_command", side_effect=[audit_result, doctor_result]), mock.patch.object(
            autorun, "write_report"
        ), mock.patch.object(autorun, "write_doctor_report"), mock.patch.object(
            autorun, "append_run_log"
        ), mock.patch.object(autorun, "notify"):
            payload = autorun.run_audit(args(), None)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "ran")
        self.assertEqual(payload["doctor_status"], "error")
        self.assertFalse(payload["doctor_ok"])

    def test_skip_doctor_is_explicit(self) -> None:
        audit_result = {
            "ok": True,
            "returncode": 0,
            "stdout": json.dumps({"findings": []}),
            "stderr": "",
        }
        with mock.patch.object(autorun, "run_command", return_value=audit_result) as run_mock, mock.patch.object(
            autorun, "write_report"
        ), mock.patch.object(autorun, "append_run_log"), mock.patch.object(autorun, "notify"):
            payload = autorun.run_audit(args(skip_doctor=True, notify=False), None)
        self.assertEqual(run_mock.call_count, 1)
        self.assertEqual(payload["doctor_status"], "skipped")

    def test_closeout_doctor_allows_expected_precommit_memory(self) -> None:
        doctor_result = {
            "ok": True,
            "returncode": 0,
            "stdout": json.dumps({"status": "ok", "summary": {"pass": 26, "warn": 0, "fail": 0}}),
            "stderr": "",
        }
        with mock.patch.object(autorun, "run_command", return_value=doctor_result) as run_mock, mock.patch.object(
            autorun, "write_doctor_report"
        ):
            report = autorun.run_doctor(30, allow_dirty_memory=True)
        self.assertEqual(report["status"], "ok")
        self.assertIn("--allow-dirty-memory", run_mock.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
