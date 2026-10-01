#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
from pathlib import Path
from typing import Any

from agent_memory_env import RuntimeTransitionError, assert_runtime_ready, env_value, expand_path


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
VAULT_ROOT = expand_path(env_value("ROOT", str(RUNTIME_ROOT / "templates" / "vault"))).resolve()
SCAN_DIRECTORIES = ("决策", "项目")
SECTION_PATTERN = re.compile(r"^##\s+决策\s*[-—–]\s*结果记录\s*$")
FIELD_PATTERN = re.compile(r"^\s*[-*]\s*([^:：]+)[:：]\s*(.*?)\s*$")
REQUIRED_FIELDS = (
    "决策日期",
    "决策问题",
    "当时选项",
    "最终选择",
    "预期结果",
    "复盘日期",
    "实际结果",
    "副作用",
    "当前结论",
    "未确定项",
)
PENDING_PREFIXES = (
    "TBD",
    "TODO",
    "PENDING",
    "UNKNOWN",
    "待定",
    "待观察",
    "待验证",
    "未验证",
    "未填写",
    "待复盘",
    "待补充",
    "尚未",
    "未知",
)
OUTCOME_FIELDS = ("实际结果", "副作用", "当前结论", "未确定项")
NO_EVIDENCE_VALUES = {"无", "无证据", "NONE", "N/A", "NA"}
OUTCOME_SCHEMA = "decision-outcome/v1"
V1_REQUIRED_FIELDS = (
    "outcome_schema",
    "decision_id",
    *REQUIRED_FIELDS,
    "outcome_status",
    "decision_ref",
    "evidence_ref",
    "后续使用证据",
    "recorded_at",
    "recorded_by",
    "confidence",
)
OUTCOME_STATUS_VALUES = {
    "pending",
    "confirmed",
    "mixed",
    "reversed",
    "superseded",
    "unverifiable",
}
RECORDED_BY_VALUES = {"human", "codex", "claude"}
CONFIDENCE_VALUES = {"high", "medium", "low"}
DECISION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$")


def is_pending_value(value: str) -> bool:
    normalized = value.strip()
    if not normalized:
        return True
    folded = normalized.casefold()
    return any(folded.startswith(prefix.casefold()) for prefix in PENDING_PREFIXES)


def has_meaningful_evidence(value: str) -> bool:
    normalized = value.strip()
    return bool(normalized) and not is_pending_value(normalized) and normalized.upper() not in NO_EVIDENCE_VALUES


def parse_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value.strip()[:10])
    except (AttributeError, ValueError):
        return None


def extract_record(text: str) -> dict[str, str] | None:
    lines = text.splitlines()
    start = next((index for index, line in enumerate(lines) if SECTION_PATTERN.match(line.strip())), None)
    if start is None:
        return None
    fields: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        match = FIELD_PATTERN.match(line)
        if match:
            fields[match.group(1).strip()] = match.group(2).strip()
    return fields


def record_status(fields: dict[str, str], as_of: dt.date) -> tuple[str, list[str], str]:
    missing = [field for field in REQUIRED_FIELDS if not fields.get(field, "").strip()]
    if missing:
        return "invalid", missing, ""
    review_date = parse_date(fields["复盘日期"])
    decision_date = parse_date(fields["决策日期"])
    if review_date is None or decision_date is None:
        invalid_dates = []
        if decision_date is None:
            invalid_dates.append("决策日期")
        if review_date is None:
            invalid_dates.append("复盘日期")
        return "invalid", invalid_dates, fields.get("复盘日期", "")
    pending = any(is_pending_value(fields[field]) for field in OUTCOME_FIELDS)
    if pending:
        return ("scheduled" if review_date > as_of else "overdue"), [], review_date.isoformat()
    return "observed", [], review_date.isoformat()


def validate_v1(fields: dict[str, str]) -> list[str]:
    """Validate the machine-readable v1 envelope without judging truth."""

    schema = fields.get("outcome_schema", "").strip()
    if not schema:
        return []
    errors: list[str] = []
    if schema != OUTCOME_SCHEMA:
        return ["outcome_schema:unsupported"]
    for field in V1_REQUIRED_FIELDS:
        if not fields.get(field, "").strip():
            errors.append(f"{field}:missing")
    decision_id = fields.get("decision_id", "").strip()
    if decision_id and not DECISION_ID_PATTERN.fullmatch(decision_id):
        errors.append("decision_id:invalid")
    outcome_status = fields.get("outcome_status", "").strip().casefold()
    if outcome_status and outcome_status not in OUTCOME_STATUS_VALUES:
        errors.append("outcome_status:invalid")
    if outcome_status in OUTCOME_STATUS_VALUES - {"pending"}:
        for field in OUTCOME_FIELDS:
            if is_pending_value(fields.get(field, "")):
                errors.append(f"{field}:pending_for_conclusion")
    recorded_by = fields.get("recorded_by", "").strip().casefold()
    if recorded_by and recorded_by not in RECORDED_BY_VALUES:
        errors.append("recorded_by:invalid")
    confidence = fields.get("confidence", "").strip().casefold()
    if confidence and confidence not in CONFIDENCE_VALUES:
        errors.append("confidence:invalid")
    if fields.get("recorded_at", "").strip() and parse_date(fields["recorded_at"]) is None:
        errors.append("recorded_at:invalid")
    # A positive/revision conclusion must point to evidence independent from
    # the memory record itself. This validates presence, not the evidence's
    # truth; live verification remains a separate responsibility.
    if outcome_status in {"confirmed", "mixed", "reversed", "superseded"} and not has_meaningful_evidence(
        fields.get("evidence_ref", "")
    ):
        errors.append("evidence_ref:required_for_conclusion")
    return list(dict.fromkeys(errors))


def scan_records(vault_root: Path, as_of: dt.date) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    corpus_files = 0
    for directory_name in SCAN_DIRECTORIES:
        directory = vault_root / directory_name
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.md")):
            if path.name.startswith("_模板") or path.name == "README.md":
                continue
            corpus_files += 1
            text = path.read_text(encoding="utf-8", errors="replace")
            fields = extract_record(text)
            if fields is None:
                continue
            status, missing_fields, review_date = record_status(fields, as_of)
            schema = fields.get("outcome_schema", "").strip()
            validation_errors = validate_v1(fields)
            if validation_errors:
                status = "invalid"
                missing_fields = [*missing_fields, *validation_errors]
            version = "v1" if schema == OUTCOME_SCHEMA else "legacy"
            outcome_status = fields.get("outcome_status", "").strip().casefold()
            records.append(
                {
                    "rel_path": path.relative_to(vault_root).as_posix(),
                    "schema": schema or "legacy",
                    "version": version,
                    "decision_id": fields.get("decision_id", "").strip(),
                    "status": status,
                    "outcome_status": outcome_status or "legacy_unclassified",
                    "review_date": review_date,
                    "missing_fields": missing_fields,
                    "evidence_recorded": has_meaningful_evidence(fields.get("后续使用证据", "")),
                    "decision_ref_recorded": has_meaningful_evidence(fields.get("decision_ref", "")),
                    "independent_evidence_ref_recorded": has_meaningful_evidence(fields.get("evidence_ref", "")),
                }
            )
    decision_id_paths: dict[str, set[str]] = {}
    for record in records:
        decision_id = str(record["decision_id"]).strip()
        if decision_id:
            decision_id_paths.setdefault(decision_id.casefold(), set()).add(str(record["rel_path"]))
    duplicate_ids = {
        normalized_id
        for normalized_id, rel_paths in decision_id_paths.items()
        if len(rel_paths) > 1
    }
    for record in records:
        decision_id = str(record["decision_id"]).strip()
        if decision_id and decision_id.casefold() in duplicate_ids:
            record["status"] = "invalid"
            record["missing_fields"] = list(
                dict.fromkeys([*record["missing_fields"], "decision_id:duplicate"])
            )
    counts = {status: sum(1 for record in records if record["status"] == status) for status in ("observed", "scheduled", "overdue", "invalid")}
    declared_outcome_status_counts = {
        status: sum(1 for record in records if record["outcome_status"] == status)
        for status in (*sorted(OUTCOME_STATUS_VALUES), "legacy_unclassified")
    }
    outcome_status_counts = {
        status: sum(
            1
            for record in records
            if record["outcome_status"] == status
            and record["status"] != "invalid"
            and (
                (status == "legacy_unclassified" and record["version"] == "legacy")
                or (status != "legacy_unclassified" and record["version"] == "v1")
            )
        )
        for status in (*sorted(OUTCOME_STATUS_VALUES), "legacy_unclassified")
    }
    v1_records = sum(1 for record in records if record["version"] == "v1")
    return {
        "as_of": as_of.isoformat(),
        "corpus_files": corpus_files,
        "eligible_files": corpus_files,  # Deprecated compatibility alias.
        "trackable_decision_denominator": None,
        "denominator_note": "corpus_files are scanned Markdown files, not a count of decisions",
        "outcome_records": len(records),
        "record_count": len(records),
        "v1_records": v1_records,
        "legacy_records": len(records) - v1_records,
        "file_coverage": (len(records) / corpus_files) if corpus_files else 0.0,
        "coverage": (len(records) / corpus_files) if corpus_files else 0.0,  # Deprecated alias.
        "status_counts": counts,
        "counts": counts,
        "outcome_status_counts": outcome_status_counts,
        "validated_outcome_status_counts": outcome_status_counts,
        "declared_outcome_status_counts": declared_outcome_status_counts,
        "records": records,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Report decision-outcome records without modifying Markdown truth.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--as-of", default="", help="Review date in YYYY-MM-DD; defaults to today.")
    parser.add_argument("--strict", action="store_true", help="Return non-zero when an included record is invalid.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        assert_runtime_ready("decision-outcomes")
    except RuntimeTransitionError as exc:
        if args.json:
            print(json.dumps({"ok": False, "reason_code": "RUNTIME_TRANSITION_INCOMPLETE"}))
        else:
            print(str(exc), file=os.sys.stderr)
        return 2
    as_of = parse_date(args.as_of) if args.as_of else dt.date.today()
    if as_of is None:
        print("invalid_as_of_date", file=os.sys.stderr)
        return 2
    payload = scan_records(VAULT_ROOT, as_of)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(
            f"outcome_records={payload['outcome_records']} corpus_files={payload['corpus_files']} "
            f"file_coverage={payload['file_coverage']:.1%} v1={payload['v1_records']} "
            f"legacy={payload['legacy_records']} as_of={payload['as_of']}"
        )
        print("trackable_decision_denominator=unknown")
        for status, count in payload["counts"].items():
            print(f"{status}={count}")
        for status, count in payload["outcome_status_counts"].items():
            print(f"outcome_status[{status}]={count}")
        for record in payload["records"]:
            print(f"{record['status']}: {record['rel_path']} review={record['review_date'] or '-'}")
    return 2 if args.strict and payload["counts"]["invalid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
