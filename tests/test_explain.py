from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "agent_memory_explain.py"
MEMORYCTL = ROOT / "scripts" / "memoryctl"


class ExplainTests(unittest.TestCase):
    def run_explain(self, reason_code: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), reason_code, "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_unclaimed_external_change_never_recommends_low_level_claim(self) -> None:
        completed = self.run_explain("UNCLAIMED_EXTERNAL_CHANGE")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        rendered = json.dumps(payload, ensure_ascii=False).casefold()
        self.assertIn("read-target", rendered)
        self.assertIn("exact adopt", rendered)
        self.assertNotIn("claim --file", rendered)

    def test_unknown_reason_code_is_structured(self) -> None:
        completed = self.run_explain("NOT_A_REAL_REASON")
        self.assertEqual(completed.returncode, 2)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["error"], "UNKNOWN_REASON_CODE")
        self.assertTrue(payload["known_reason_codes"])

    def test_expired_intent_explains_only_high_level_exact_recovery(self) -> None:
        completed = self.run_explain("INTENT_EXPIRED")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        rendered = json.dumps(payload, ensure_ascii=False).casefold()
        self.assertIn("original write apply", rendered)
        self.assertIn("bounded recovery window", rendered)
        self.assertIn("write read-target", rendered)
        self.assertNotIn("claim --file", rendered)
        self.assertNotIn("agent_memory_claim.py", rendered)

    def test_expired_committed_rejection_codes_have_safe_current_route(self) -> None:
        for reason_code in (
            "APPLY_RECOVERY_REQUIRED",
            "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
            "EXPIRED_VALIDATED_RECOVERY_GIT_DIVERGED",
            "EXPIRED_VALIDATED_RECOVERY_WINDOW_ELAPSED",
            "EXPIRED_VALIDATED_RECOVERY_WORKTREE_DIRTY",
        ):
            with self.subTest(reason_code=reason_code):
                completed = self.run_explain(reason_code)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(completed.stdout)
                rendered = json.dumps(payload, ensure_ascii=False).casefold()
                self.assertIn("write apply", rendered)
                self.assertNotIn("claim --file", rendered)
                self.assertNotIn("agent_memory_claim.py", rendered)

    def test_governance_and_generated_index_codes_use_current_gateway_route(self) -> None:
        for reason_code in (
            "PATH_POLICY_DOWNGRADE_FORBIDDEN",
            "TEMPORAL_POLICY_REQUIRED",
            "REVIEW_POLICY_REQUIRED",
            "ACTION_SENSITIVE_FACT_REQUIRED",
            "GOVERNANCE_MIGRATION_TARGET_INVALID",
            "GENERATED_INDEX_OTHER_SESSION_DIRTY",
            "GENERATED_INDEX_BASE_UNSAFE",
            "GENERATED_INDEX_ROLLBACK_FAILED",
        ):
            with self.subTest(reason_code=reason_code):
                completed = self.run_explain(reason_code)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                payload = json.loads(completed.stdout)
                self.assertTrue(payload["ok"])
                rendered = json.dumps(payload, ensure_ascii=False).casefold()
                self.assertNotIn("claim --file", rendered)
                self.assertNotIn("agent_memory_claim.py", rendered)

    def test_path_policy_downgrade_explains_intent_bound_gateway_recovery(self) -> None:
        completed = self.run_explain("PATH_POLICY_DOWNGRADE_FORBIDDEN")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        rendered = json.dumps(payload, ensure_ascii=False).casefold()
        self.assertIn("read-target", rendered)
        self.assertIn("write prepare", rendered)
        self.assertIn("apply", rendered)
        self.assertIn("canonical", rendered)
        self.assertIn("intent-bound", rendered)
        self.assertNotIn("claim --file", rendered)

    def test_unsafe_risk_automation_requires_human_review_and_gateway_reprepare(self) -> None:
        completed = self.run_explain("RISK_AUTOMATION_CLASSIFICATION_UNSAFE")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        rendered = json.dumps(payload, ensure_ascii=False).casefold()
        self.assertIn("human review", rendered)
        self.assertIn("risk_class", rendered)
        self.assertIn("ordinary", rendered)
        self.assertIn("write read-target", rendered)
        self.assertIn("write prepare", rendered)
        self.assertIn("apply", rendered)
        self.assertNotIn("claim --file", rendered)
        self.assertNotIn("agent_memory_claim.py", rendered)

    def test_memoryctl_dispatches_explain(self) -> None:
        completed = subprocess.run(
            [str(MEMORYCTL), "explain", "PROJECT_CONTEXT_UNKNOWN", "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["reason_code"], "PROJECT_CONTEXT_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
