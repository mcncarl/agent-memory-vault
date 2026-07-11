from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))


def load_closeout():
    path = SCRIPTS_ROOT / "agent_memory_closeout.py"
    spec = importlib.util.spec_from_file_location("test_prewrite_closeout_module", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrewriteReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_closeout()

    @staticmethod
    def args(prewrite: str) -> Namespace:
        return Namespace(
            prewrite=prewrite,
            limit=8,
            no_zvec=True,
            actor="codex",
            trigger="test",
            session_id="",
        )

    def test_search_memory_preserves_structured_failure(self) -> None:
        warning = "sqlite index missing: <state-index>"
        payload = {
            "results": [],
            "warnings": [warning],
            "backend_status": {
                "sqlite": {"status": "error", "results": 0, "warnings": [warning]},
                "zvec": {"status": "skipped", "results": 0, "warnings": []},
                "rg": {"status": "skipped", "results": 0, "warnings": []},
            },
        }
        result = {
            "ok": False,
            "returncode": 2,
            "stdout": json.dumps(payload),
            "stderr": "",
        }
        with mock.patch.object(self.module, "run_command", return_value=result):
            rows, warnings, backend_status = self.module.search_memory("ordinary query")

        self.assertEqual(rows, [])
        self.assertEqual(warnings, [warning])
        self.assertEqual(backend_status["sqlite"]["status"], "error")

    def test_prewrite_search_failure_is_not_add_or_ask_user(self) -> None:
        args = self.args("ordinary new memory")
        with mock.patch.object(
            self.module,
            "search_memory",
            return_value=([], ["sqlite index missing"], {"sqlite": {"status": "error"}}),
        ):
            payload = self.module.run_prewrite(args)

        self.assertEqual(payload["status"], "error")
        self.assertIsNone(payload["recommended_action"])
        self.assertEqual(
            payload["recommendation_unavailable_reason"],
            "reconcile_search_unhealthy",
        )

    def test_optional_vector_warning_does_not_block_sqlite(self) -> None:
        args = self.args("ordinary new memory")
        with mock.patch.object(
            self.module,
            "search_memory",
            return_value=(
                [],
                ["zvec not installed"],
                {
                    "sqlite": {"status": "ok"},
                    "zvec": {"status": "error"},
                },
            ),
        ):
            payload = self.module.run_prewrite(args)

        self.assertEqual(payload["status"], "warning")
        self.assertEqual(payload["recommended_action"], "ADD")

    def test_prewrite_bounds_long_search_query(self) -> None:
        captured: list[str] = []

        def fake_search(query, **_kwargs):
            captured.append(query)
            return [], [], {"sqlite": {"status": "ok"}}

        long_text = "Cross-platform image workflow records stable verification steps. " * 500
        with mock.patch.object(self.module, "search_memory", side_effect=fake_search):
            payload = self.module.run_prewrite(self.args(long_text))

        self.assertEqual(payload["recommended_action"], "ADD")
        self.assertEqual(len(captured), 1)
        self.assertLessEqual(len(captured[0]), self.module.RECONCILE_QUERY_MAX_CHARS)
        self.assertLess(len(captured[0]), len(long_text))

    def test_long_description_matches_existing_title(self) -> None:
        row = {
            "title": "Cross-platform image converter",
            "rel_path": "projects/cross-platform-image-converter.md",
            "summary": "The project is in technical validation.",
            "hit": "",
        }
        text = (
            "Cross-platform image converter supports batch processing, metadata retention, "
            "failure retries, output validation, and a reusable maintenance workflow."
        )

        action, target, metrics = self.module.prewrite_recommendation(text, [row])

        self.assertEqual(action, "UPDATE")
        self.assertIs(target, row)
        self.assertTrue(metrics["title_match"])

    def test_postwrite_search_failure_is_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            vault = Path(raw) / "vault"
            path = vault / "项目" / "new.md"
            path.parent.mkdir(parents=True)
            path.write_text("# New memory\n", encoding="utf-8")
            self.module.VAULT_ROOT = vault
            entry = self.module.GitEntry("A", "vault/项目/new.md", path)
            args = Namespace(
                reconcile_all=False,
                limit=8,
                no_zvec=True,
                merge_threshold=0.42,
                merge_coverage_threshold=0.35,
                semantic_merge_threshold=0.32,
            )
            with mock.patch.object(
                self.module,
                "search_memory",
                return_value=(
                    [],
                    ["sqlite index missing"],
                    {"sqlite": {"status": "error"}},
                ),
            ):
                findings, warnings = self.module.postwrite_reconcile([entry], args)

        self.assertTrue(warnings)
        self.assertEqual(findings[0]["action"], "ASK_USER")
        self.assertEqual(findings[0]["reason"], "reconcile_search_unhealthy")


if __name__ == "__main__":
    unittest.main()
