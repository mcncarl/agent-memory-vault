from __future__ import annotations

import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_decision_outcomes as outcomes


def note(actual: str, review: str = "2026-07-20", omit: str = "", **overrides: str) -> str:
    values = {
        "决策日期": "2026-07-01",
        "决策问题": "示例问题",
        "当时选项": "A；B",
        "最终选择": "A",
        "预期结果": "示例预期",
        "复盘日期": review,
        "实际结果": actual,
        "副作用": "无",
        "当前结论": "保留",
        "未确定项": "无",
        "后续使用证据": "后续测试已引用",
    }
    values.update(overrides)
    if omit:
        values.pop(omit)
    lines = ["# Example", "", "## 决策—结果记录", ""]
    lines.extend(f"- {key}：{value}" for key, value in values.items())
    return "\n".join(lines) + "\n"


def v1_note(
    status: str = "confirmed",
    evidence_ref: str = "git:abc123",
    decision_id: str = "decision-20260701-example",
) -> str:
    return note(
        "达到预期",
        outcome_schema="decision-outcome/v1",
        decision_id=decision_id,
        outcome_status=status,
        decision_ref="git:def456:决策原文",
        evidence_ref=evidence_ref,
        recorded_at="2026-07-20",
        recorded_by="codex",
        confidence="high",
    )


class DecisionOutcomeTests(unittest.TestCase):
    def test_states_and_privacy_safe_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            (root / "决策").mkdir()
            (root / "项目").mkdir()
            (root / "决策" / "observed.md").write_text(note("达到预期"), encoding="utf-8")
            (root / "决策" / "scheduled.md").write_text(note("TBD", "2026-07-21"), encoding="utf-8")
            (root / "项目" / "overdue.md").write_text(note("待观察", "2026-07-18"), encoding="utf-8")
            (root / "决策" / "invalid.md").write_text(note("达到预期", omit="副作用"), encoding="utf-8")
            (root / "决策" / "_模板-ignore.md").write_text(note("secret template body"), encoding="utf-8")

            report = outcomes.scan_records(root, dt.date(2026, 7, 19))

        self.assertEqual(report["counts"], {"observed": 1, "scheduled": 1, "overdue": 1, "invalid": 1})
        self.assertEqual(report["record_count"], 4)
        self.assertEqual(report["corpus_files"], 4)
        self.assertEqual(report["outcome_records"], 4)
        self.assertIsNone(report["trackable_decision_denominator"])
        self.assertEqual(report["legacy_records"], 4)
        self.assertEqual(report["v1_records"], 0)
        self.assertNotIn("示例问题", str(report))
        invalid = next(record for record in report["records"] if record["status"] == "invalid")
        self.assertEqual(invalid["missing_fields"], ["副作用"])

    def test_invalid_date_is_invalid(self) -> None:
        fields = outcomes.extract_record(note("TBD", "not-a-date"))
        self.assertIsNotNone(fields)
        status, missing, _ = outcomes.record_status(fields or {}, dt.date(2026, 7, 19))
        self.assertEqual(status, "invalid")
        self.assertEqual(missing, ["复盘日期"])

    def test_any_unfinished_outcome_field_keeps_record_pending(self) -> None:
        for field, value in (
            ("实际结果", "unknown"),
            ("副作用", "待定"),
            ("当前结论", "TBD - 等待数据"),
            ("未确定项", "未填写"),
        ):
            with self.subTest(field=field):
                fields = outcomes.extract_record(note("达到预期", **{field: value}))
                status, missing, _ = outcomes.record_status(fields or {}, dt.date(2026, 7, 19))
                self.assertEqual(status, "scheduled")
                self.assertEqual(missing, [])

    def test_placeholder_evidence_is_not_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            (root / "决策").mkdir()
            (root / "决策" / "pending-evidence.md").write_text(
                note("达到预期", **{"后续使用证据": "TBD"}),
                encoding="utf-8",
            )
            report = outcomes.scan_records(root, dt.date(2026, 7, 19))
        self.assertFalse(report["records"][0]["evidence_recorded"])
        self.assertFalse(outcomes.has_meaningful_evidence("无"))

    def test_v1_record_reports_schema_status_and_evidence_separately(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            (root / "决策").mkdir()
            (root / "决策" / "v1.md").write_text(v1_note(), encoding="utf-8")
            report = outcomes.scan_records(root, dt.date(2026, 7, 21))
        self.assertEqual(report["v1_records"], 1)
        self.assertEqual(report["legacy_records"], 0)
        self.assertEqual(report["outcome_status_counts"]["confirmed"], 1)
        record = report["records"][0]
        self.assertEqual(record["decision_id"], "decision-20260701-example")
        self.assertTrue(record["decision_ref_recorded"])
        self.assertTrue(record["independent_evidence_ref_recorded"])
        self.assertEqual(record["missing_fields"], [])

    def test_v1_conclusion_without_independent_evidence_is_invalid(self) -> None:
        fields = outcomes.extract_record(v1_note(evidence_ref="待验证")) or {}
        self.assertIn("evidence_ref:required_for_conclusion", outcomes.validate_v1(fields))
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            (root / "决策").mkdir()
            (root / "决策" / "unsupported.md").write_text(v1_note(evidence_ref="待验证"), encoding="utf-8")
            report = outcomes.scan_records(root, dt.date(2026, 7, 21))
        self.assertEqual(report["counts"]["invalid"], 1)
        self.assertEqual(report["declared_outcome_status_counts"]["confirmed"], 1)
        self.assertEqual(report["validated_outcome_status_counts"]["confirmed"], 0)

    def test_v1_conclusion_with_pending_result_fields_is_not_validated(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            (root / "决策").mkdir()
            (root / "决策" / "premature.md").write_text(
                v1_note().replace("- 实际结果：达到预期", "- 实际结果：TBD"),
                encoding="utf-8",
            )
            report = outcomes.scan_records(root, dt.date(2026, 7, 21))
        self.assertEqual(report["counts"]["invalid"], 1)
        self.assertEqual(report["declared_outcome_status_counts"]["confirmed"], 1)
        self.assertEqual(report["validated_outcome_status_counts"]["confirmed"], 0)
        self.assertIn("实际结果:pending_for_conclusion", report["records"][0]["missing_fields"])

    def test_legacy_record_cannot_self_declare_a_validated_truth_status(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            (root / "决策").mkdir()
            (root / "决策" / "legacy.md").write_text(
                note("达到预期", outcome_status="confirmed"),
                encoding="utf-8",
            )
            report = outcomes.scan_records(root, dt.date(2026, 7, 21))
        self.assertEqual(report["declared_outcome_status_counts"]["confirmed"], 1)
        self.assertEqual(report["validated_outcome_status_counts"]["confirmed"], 0)
        self.assertEqual(report["validated_outcome_status_counts"]["legacy_unclassified"], 0)

    def test_unverifiable_v1_may_explicitly_lack_independent_evidence(self) -> None:
        fields = outcomes.extract_record(v1_note(status="unverifiable", evidence_ref="无证据")) or {}
        self.assertEqual(outcomes.validate_v1(fields), [])

    def test_duplicate_decision_ids_across_files_are_all_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            root = Path(raw_tmp)
            (root / "决策").mkdir()
            (root / "项目").mkdir()
            (root / "决策" / "first.md").write_text(
                v1_note(decision_id="decision-20260701-Shared"), encoding="utf-8"
            )
            (root / "项目" / "second.md").write_text(
                v1_note(decision_id="decision-20260701-shared"), encoding="utf-8"
            )
            report = outcomes.scan_records(root, dt.date(2026, 7, 21))
        self.assertEqual(report["counts"]["invalid"], 2)
        self.assertEqual(report["validated_outcome_status_counts"]["confirmed"], 0)
        self.assertTrue(
            all("decision_id:duplicate" in record["missing_fields"] for record in report["records"])
        )

    def test_decision_template_contains_a_valid_v1_envelope(self) -> None:
        template = (REPO_ROOT / "templates" / "vault" / "决策" / "_模板-决策.md").read_text(
            encoding="utf-8"
        )
        fields = outcomes.extract_record(template) or {}
        self.assertEqual(fields.get("outcome_schema"), outcomes.OUTCOME_SCHEMA)
        self.assertEqual(outcomes.validate_v1(fields), [])
        self.assertFalse(outcomes.has_meaningful_evidence(fields.get("evidence_ref", "")))


if __name__ == "__main__":
    unittest.main()
