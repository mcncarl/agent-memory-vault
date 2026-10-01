from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER = REPO_ROOT / "scripts" / "agent_memory_policy_benchmark.py"


def run_benchmark(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(RUNNER), *args, "--json"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


class PolicyBenchmarkTests(unittest.TestCase):
    def test_bundled_public_fixtures_cover_all_policy_results(self) -> None:
        completed = run_benchmark()
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(payload["datasets"]), 2)
        by_kind = {item["dataset"]["kind"]: item for item in payload["datasets"]}
        self.assertEqual(by_kind["reconcile"]["metrics"]["cases"], 6)
        self.assertEqual(by_kind["reconcile"]["metrics"]["accuracy"], 1.0)
        self.assertEqual(
            {record["result"] for record in by_kind["reconcile"]["records"]},
            {"ADD", "UPDATE", "NOOP", "MARK_OUTDATED", "MERGE_REQUIRED", "ASK_USER"},
        )
        outdated = next(record for record in by_kind["reconcile"]["records"] if record["result"] == "MARK_OUTDATED")
        self.assertEqual(outdated["result_origin"], "annotate_result_policy")
        self.assertGreaterEqual(by_kind["safety"]["metrics"]["cases"], 5)
        self.assertEqual(by_kind["safety"]["metrics"]["accuracy"], 1.0)
        self.assertEqual(
            {record["result"] for record in by_kind["safety"]["records"]},
            {"ALLOW", "ASK_USER", "BLOCK"},
        )

    def test_explicit_file_is_private_even_when_it_declares_public(self) -> None:
        private_text = "PRIVATE_SENTENCE_SHOULD_NEVER_APPEAR"
        private_expected = "ALLOW"
        with tempfile.TemporaryDirectory(prefix="private-policy-path-") as raw_root:
            path = Path(raw_root) / "private-secret-filename.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "name": "PRIVATE_DATASET_NAME",
                        "privacy": "public_sample",
                        "kind": "safety",
                        "cases": [
                            {
                                "id": "private-001",
                                "input": private_text,
                                "source_class": "user_direct",
                                "knowledge_kind": "fact",
                                "expected": private_expected,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            completed = run_benchmark("--benchmark-file", str(path))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertNotIn(private_text, completed.stdout)
            self.assertNotIn("PRIVATE_DATASET_NAME", completed.stdout)
            self.assertNotIn("private-001", completed.stdout)
            self.assertNotIn(str(path.resolve()), completed.stdout)
            self.assertNotIn("private-secret-filename.json", completed.stdout)
            payload = json.loads(completed.stdout)
            dataset = payload["datasets"][0]
            self.assertEqual(dataset["dataset"]["privacy"], "private_local")
            self.assertEqual(
                set(dataset["records"][0]),
                {"case_ref", "input_sha256", "input_length", "result"},
            )
            self.assertRegex(dataset["records"][0]["case_ref"], r"^case-001-[0-9a-f]{12}$")

    def test_private_details_require_explicit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = Path(raw_root) / "fixture.json"
            path.write_text(
                json.dumps(
                    {
                        "privacy": "private_local",
                        "kind": "reconcile",
                        "cases": [
                            {
                                "id": "detail-001",
                                "input": "DETAILS_VISIBLE_ONLY_WITH_FLAG",
                                "source_class": "user_direct",
                                "knowledge_kind": "fact",
                                "rows": [],
                                "expected": "ADD",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            hidden = run_benchmark("--benchmark-file", str(path))
            shown = run_benchmark("--benchmark-file", str(path), "--show-private-details")
            self.assertNotIn("DETAILS_VISIBLE_ONLY_WITH_FLAG", hidden.stdout)
            self.assertIn("DETAILS_VISIBLE_ONLY_WITH_FLAG", shown.stdout)
            self.assertNotIn("detail-001", hidden.stdout)
            self.assertIn("detail-001", shown.stdout)

    def test_private_case_exception_does_not_emit_exception_text(self) -> None:
        with tempfile.TemporaryDirectory(prefix="exception-private-path-") as raw_root:
            path = Path(raw_root) / "fixture.json"
            path.write_text(
                json.dumps(
                    {
                        "privacy": "private_local",
                        "kind": "reconcile",
                        "cases": [
                            {
                                "id": "exception-001",
                                "input": "PRIVATE_EXCEPTION_INPUT",
                                "source_class": "user_direct",
                                "knowledge_kind": "fact",
                                "rows": [{"source_details": {"zvec_raw_distance": {"bad": "value"}}}],
                                "expected": "ADD",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            completed = run_benchmark("--benchmark-file", str(path))
            self.assertNotIn("PRIVATE_EXCEPTION_INPUT", completed.stdout)
            self.assertNotIn(str(path.resolve()), completed.stdout)
            payload = json.loads(completed.stdout)
            record = payload["datasets"][0]["records"][0]
            self.assertEqual(set(record), {"case_ref", "input_sha256", "input_length", "result"})
            self.assertNotIn("exception-001", completed.stdout)

    def test_explicit_input_errors_are_content_free_and_nonzero(self) -> None:
        with tempfile.TemporaryDirectory(prefix="PRIVATE_POLICY_DIR_") as raw_root:
            root = Path(raw_root)
            invalid_json = root / "PRIVATE_POLICY_INVALID_JSON_FILENAME.json"
            invalid_json.write_text("PRIVATE_POLICY_INVALID_JSON_CONTENT{", encoding="utf-8")
            invalid_fixture = root / "PRIVATE_POLICY_INVALID_FIXTURE_FILENAME.json"
            invalid_fixture.write_text(
                json.dumps(
                    {
                        "privacy": "private_local",
                        "kind": "safety",
                        "cases": [
                            {
                                "id": "PRIVATE_POLICY_INVALID_CASE_ID",
                                "input": "PRIVATE_POLICY_INVALID_INPUT",
                                "expected": "PRIVATE_POLICY_INVALID_EXPECTED",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            missing = root / "PRIVATE_POLICY_MISSING_FILENAME.json"
            scenarios = [
                (missing, "dataset_unreadable"),
                (invalid_json, "dataset_invalid_json"),
                (invalid_fixture, "case_expected_is_unsupported"),
            ]
            for path, expected_error in scenarios:
                with self.subTest(expected_error=expected_error):
                    completed = run_benchmark("--benchmark-file", str(path))
                    self.assertEqual(completed.returncode, 2)
                    combined = completed.stdout + completed.stderr
                    self.assertEqual(json.loads(completed.stdout)["error"], expected_error)
                    self.assertNotIn(str(root), combined)
                    self.assertNotIn(path.name, combined)
                    self.assertNotIn("PRIVATE_POLICY_INVALID_JSON_CONTENT", combined)
                    self.assertNotIn("PRIVATE_POLICY_INVALID_CASE_ID", combined)
                    self.assertNotIn("PRIVATE_POLICY_INVALID_INPUT", combined)
                    self.assertNotIn("PRIVATE_POLICY_INVALID_EXPECTED", combined)
                    self.assertNotIn("Traceback", combined)


if __name__ == "__main__":
    unittest.main()
