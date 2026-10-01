#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from argparse import Namespace
from datetime import date
from pathlib import Path
from typing import Any

import agent_memory_closeout as closeout
import agent_memory_search as memory_search
import agent_memory_safety as safety


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASETS = {
    "reconcile": REPO_ROOT / "benchmarks" / "public-policy-reconcile.json",
    "safety": REPO_ROOT / "benchmarks" / "public-policy-safety.json",
}
VALID_KINDS = frozenset(DEFAULT_DATASETS)
VALID_RECONCILE_RESULTS = {"ADD", "UPDATE", "NOOP", "MARK_OUTDATED", "MERGE_REQUIRED", "ASK_USER"}
VALID_SAFETY_RESULTS = {"ALLOW", "ASK_USER", "BLOCK"}
CURRENT_STATUSES = {"active", "current", "validated", "observed"}
OUTDATED_CONTEXTS = {"", "superseded", "expiry_review"}
MAX_DATASET_BYTES = 2 * 1024 * 1024
MAX_CASES = 200
MAX_INPUT_CHARS = 20_000


class DatasetError(ValueError):
    """A bounded, content-free benchmark validation error."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redacted_case_ref(case_id: object, ordinal: int) -> str:
    digest = sha256_text(str(case_id))[:12]
    return f"case-{ordinal:03d}-{digest}"


def require_string(item: dict[str, Any], key: str, *, allow_empty: bool = False) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise DatasetError(f"case_{key}_must_be_string")
    value = value.strip()
    if not allow_empty and not value:
        raise DatasetError(f"case_{key}_must_be_nonempty")
    return value


def validate_case(raw: object, *, kind: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise DatasetError("case_must_be_object")
    case_id = require_string(raw, "id")
    text = require_string(raw, "input")
    if len(text) > MAX_INPUT_CHARS:
        raise DatasetError("case_input_too_large")
    expected = require_string(raw, "expected").upper()
    valid_expected = VALID_RECONCILE_RESULTS if kind == "reconcile" else VALID_SAFETY_RESULTS
    if expected not in valid_expected:
        raise DatasetError("case_expected_is_unsupported")

    source_class = str(raw.get("source_class") or "user_direct").strip().lower()
    knowledge_kind = str(raw.get("knowledge_kind") or "fact").strip().lower()
    if source_class not in safety.SOURCE_CLASSES:
        raise DatasetError("case_source_class_is_unsupported")
    if knowledge_kind not in safety.KNOWLEDGE_KINDS:
        raise DatasetError("case_knowledge_kind_is_unsupported")
    evidence_ref = str(raw.get("evidence_ref") or "")
    asserted_by = str(raw.get("asserted_by") or "benchmark")

    rows: list[dict[str, Any]] = []
    current_status = str(raw.get("current_status") or "").strip().lower()
    valid_until = str(raw.get("valid_until") or "").strip()
    as_of = str(raw.get("as_of") or "").strip()
    explicit_action_context = str(raw.get("explicit_action_context") or "").strip().lower()
    if len(current_status) > 40:
        raise DatasetError("case_current_status_is_invalid")
    if explicit_action_context not in OUTDATED_CONTEXTS:
        raise DatasetError("case_explicit_action_context_is_unsupported")
    for key, value in (("valid_until", valid_until), ("as_of", as_of)):
        if value:
            try:
                date.fromisoformat(value)
            except ValueError as exc:
                raise DatasetError(f"case_{key}_must_be_iso_date") from exc
    if kind == "reconcile":
        raw_rows = raw.get("rows", [])
        if not isinstance(raw_rows, list) or len(raw_rows) > 100:
            raise DatasetError("case_rows_must_be_bounded_array")
        if any(not isinstance(row, dict) for row in raw_rows):
            raise DatasetError("case_rows_must_contain_objects")
        rows = [dict(row) for row in raw_rows]

    return {
        "id": case_id,
        "input": text,
        "expected": expected,
        "source_class": source_class,
        "knowledge_kind": knowledge_kind,
        "evidence_ref": evidence_ref,
        "asserted_by": asserted_by,
        "rows": rows,
        "current_status": current_status,
        "valid_until": valid_until,
        "as_of": as_of,
        "explicit_action_context": explicit_action_context,
    }


def load_dataset(path: Path, *, explicit: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        raw_bytes = path.read_bytes()
    except (OSError, RuntimeError, ValueError) as exc:
        raise DatasetError("dataset_unreadable") from exc
    if len(raw_bytes) > MAX_DATASET_BYTES:
        raise DatasetError("dataset_too_large")
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatasetError("dataset_invalid_json") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("cases"), list):
        raise DatasetError("dataset_requires_object_with_cases")

    kind = str(raw.get("kind") or "").strip().lower()
    if kind not in VALID_KINDS:
        raise DatasetError("dataset_kind_is_unsupported")
    declared_privacy = str(raw.get("privacy") or "private_local").strip().lower()
    if declared_privacy not in {"public_sample", "private_local"}:
        raise DatasetError("dataset_privacy_is_unsupported")
    raw_cases = raw["cases"]
    if not raw_cases or len(raw_cases) > MAX_CASES:
        raise DatasetError("dataset_case_count_is_invalid")

    cases = [validate_case(item, kind=kind) for item in raw_cases]
    ids = [str(item["id"]) for item in cases]
    if len(set(ids)) != len(ids):
        raise DatasetError("dataset_case_ids_must_be_unique")
    try:
        schema_version = int(raw.get("schema_version") or 1)
    except (TypeError, ValueError) as exc:
        raise DatasetError("dataset_schema_version_is_invalid") from exc
    display_path = str(path.resolve()) if explicit else path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    return (
        {
            "schema_version": schema_version,
            "kind": kind,
            "name": str(raw.get("name") or path.stem),
            # A user-supplied file is always private. File contents cannot
            # self-authorize verbose output.
            "privacy": "private_local" if explicit else declared_privacy,
            "declared_privacy": declared_privacy,
            "path": display_path,
            "sha256": sha256_bytes(raw_bytes),
        },
        cases,
    )


def assess_case(case: dict[str, Any]) -> dict[str, Any]:
    return safety.assess_source(
        str(case["input"]),
        source_class=str(case["source_class"]),
        knowledge_kind=str(case["knowledge_kind"]),
        asserted_by=str(case["asserted_by"]),
        evidence_ref=str(case["evidence_ref"]),
    )


def should_mark_outdated(case: dict[str, Any]) -> bool:
    """Exercise the production time policy; never award a synthetic pass."""
    if str(case.get("current_status", "")) not in CURRENT_STATUSES:
        return False
    context = str(case.get("explicit_action_context", ""))
    if context == "expiry_review":
        result = memory_search.SearchResult(
            path="/benchmark/fact.md",
            rel_path="决策/benchmark-fact.md",
            status="active",
            valid_until=str(case.get("valid_until", "")),
        )
        memory_search.annotate_result_policy(
            result,
            Namespace(as_of=str(case.get("as_of", "")), current_project=""),
        )
        return result.time_status == "expired"
    return False


def evaluate_case(kind: str, case: dict[str, Any]) -> tuple[str, str, str]:
    assessment = assess_case(case)
    decision = str(assessment["decision"])
    if kind == "safety":
        return decision, str(assessment["reason_code"]), "assess_source"
    if decision != "ALLOW":
        return decision, str(assessment["reason_code"]), "assess_source"
    if should_mark_outdated(case):
        return "MARK_OUTDATED", "EXPLICIT_TEMPORAL_OR_SUPERSESSION_CONTEXT", "annotate_result_policy"
    result, _best_row, _metrics = closeout.prewrite_recommendation(
        str(case["input"]), list(case["rows"])
    )
    return result, "RECONCILIATION_RESULT", "prewrite_recommendation"


def redacted_dataset(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": metadata["schema_version"],
        "kind": metadata["kind"],
        "privacy": "private_local",
        "sha256": metadata["sha256"],
    }


def run_dataset(
    metadata: dict[str, Any],
    cases: list[dict[str, Any]],
    *,
    show_private_details: bool,
) -> dict[str, Any]:
    private_redacted = metadata["privacy"] == "private_local" and not show_private_details
    records: list[dict[str, Any]] = []
    passed = 0
    for ordinal, case in enumerate(cases, 1):
        try:
            result, reason_code, result_origin = evaluate_case(str(metadata["kind"]), case)
        except Exception:
            # Never propagate exception text: a dependency may include source
            # content or an absolute local path in its message.
            result, reason_code, result_origin = "ERROR", "CASE_EXECUTION_FAILED", "redacted_error"
        matched = result == case["expected"]
        passed += int(matched)
        base = {
            "input_sha256": sha256_text(str(case["input"])),
            "input_length": len(str(case["input"])),
            "result": result,
        }
        if private_redacted:
            # Privacy contract: these are the only per-case fields allowed for
            # private fixtures without explicit detail authorization.
            records.append({"case_ref": redacted_case_ref(case["id"], ordinal), **base})
        else:
            records.append(
                {
                    "id": case["id"],
                    **base,
                    "input": case["input"],
                    "expected": case["expected"],
                    "passed": matched,
                    "source_class": case["source_class"],
                    "knowledge_kind": case["knowledge_kind"],
                    "reason_code": reason_code,
                    "result_origin": result_origin,
                }
            )
    total = len(cases)
    return {
        "status": "ok" if passed == total else "failed_gate",
        "dataset": redacted_dataset(metadata) if private_redacted else dict(metadata),
        "metrics": {
            "cases": total,
            "passed": passed,
            "failed": total - passed,
            "accuracy": passed / total if total else 0.0,
        },
        "records": records,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline reconciliation and source-safety policy benchmark.")
    parser.add_argument(
        "--benchmark-file",
        action="append",
        default=[],
        help="JSON policy fixture. Repeatable. Every explicitly supplied file is private by default.",
    )
    parser.add_argument("--kind", choices=("all", "reconcile", "safety"), default="all")
    parser.add_argument("--show-private-details", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    selected: list[tuple[Path, bool]]
    reports: list[dict[str, Any]] = []
    try:
        if args.benchmark_file:
            selected = [(Path(value).expanduser(), True) for value in args.benchmark_file]
        else:
            kinds = VALID_KINDS if args.kind == "all" else {args.kind}
            selected = [(DEFAULT_DATASETS[kind], False) for kind in sorted(kinds)]
        for path, explicit in selected:
            metadata, cases = load_dataset(path, explicit=explicit)
            if args.kind != "all" and metadata["kind"] != args.kind:
                continue
            reports.append(run_dataset(metadata, cases, show_private_details=args.show_private_details))
    except (DatasetError, OSError, RuntimeError, ValueError) as exc:
        error_code = str(exc) if isinstance(exc, DatasetError) else "dataset_unreadable"
        payload = {"status": "error", "error": error_code}
        print(
            json.dumps(payload, ensure_ascii=False, indent=2)
            if args.json
            else f"policy-benchmark=error {error_code}"
        )
        return 2

    if not reports:
        payload = {"status": "error", "error": "no_datasets_selected"}
        print(json.dumps(payload, ensure_ascii=False, indent=2) if args.json else "policy-benchmark=error no_datasets_selected")
        return 2
    failed = any(report["status"] != "ok" for report in reports)
    payload = {"status": "failed_gate" if failed else "ok", "datasets": reports}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"policy-benchmark={payload['status']}")
        for report in reports:
            metrics = report["metrics"]
            print(
                f"kind={report['dataset']['kind']} cases={metrics['cases']} "
                f"passed={metrics['passed']} accuracy={metrics['accuracy']:.3f}"
            )
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
