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

from tests.test_retrieve import TempVault, markdown, SCRIPTS
import agent_memory_search as search
import agent_memory_retrieve as retrieve


class SavedMemoryConsistencyTests(unittest.TestCase):
    def test_codex_and_claude_use_the_same_shared_retrieval_contract(self):
        with tempfile.TemporaryDirectory() as raw:
            vault = TempVault(Path(raw))
            vault.write("项目/Shared.md", markdown("Shared", project_id="shared-project", status="pending_verification"))
            vault.init_git()
            vault.index()
            outcomes = []
            for actor in ("codex", "claude"):
                env = dict(vault.env)
                env["AGENT_MEMORY_SESSION_ID"] = actor + "-isolated-contract-test"
                command = [sys.executable, "-I", "-S", str(SCRIPTS / "memoryctl"),
                           "--actor", actor, "retrieve", "retrievalprobe", "--json",
                           "--current-project", "shared-project", "--semantic-mode", "off", "--max-results", "5"]
                completed = subprocess.run(command, env=env, text=True, capture_output=True, timeout=30)
                self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
                payload = json.loads(completed.stdout)
                outcomes.append([(item["relative_path"], item["sha256"], item["can_authorize_action"])
                                 for item in payload["results"]])
            self.assertEqual(outcomes[0], outcomes[1])
            self.assertEqual(len(outcomes[0]), 1)
            self.assertFalse(outcomes[0][0][2])

    def test_missing_and_same_size_backdated_content_are_visible_then_reindex_clears_warning(self):
        with tempfile.TemporaryDirectory() as raw:
            vault = TempVault(Path(raw))
            note = vault.write("项目/Original.md", markdown("Original"))
            vault.index()
            with mock.patch.object(search, "VAULT_ROOT", vault.vault), mock.patch.object(search, "STATE_DB", vault.state_db):
                self.assertEqual(search.index_projection_health()["status"], "ok")
                stamp = note.stat()
                note.write_text(note.read_text().replace("searchable", "searchablE"))
                os.utime(note, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
                vault.write("项目/New.md", markdown("New"))
                result = search.index_projection_health()
                self.assertEqual(result, {"status": "stale", "missing_count": 1, "changed_count": 1, "deleted_count": 0})
                vault.index()
                self.assertEqual(search.index_projection_health()["status"], "ok")

    def test_projection_check_does_not_follow_symlinks_outside_vault(self):
        with tempfile.TemporaryDirectory() as raw:
            vault = TempVault(Path(raw))
            vault.index()
            external = Path(raw) / "external.md"
            external.write_text("private external bytes")
            (vault.vault / "external.md").symlink_to(external)
            with mock.patch.object(search, "VAULT_ROOT", vault.vault), mock.patch.object(search, "STATE_DB", vault.state_db):
                self.assertEqual(search.index_projection_health()["status"], "unavailable")

    def test_runtime_bound_claim_becomes_reference_on_upgrade_without_hiding_text(self):
        metadata = {
            "valid_until": "", "verified_at": "2026-09-20", "verified_at_source": "frontmatter",
            "review_after_days": 90, "verification_mode": "", "explicit_live_verification": False,
            "meta": {"runtime_manifest_sha256": "a" * 64},
        }
        with mock.patch.object(search.shadow_gate, "runtime_binding", return_value={"manifest_sha256": "b" * 64}):
            verification, reasons, _ = retrieve._live_verification(metadata, dt.date(2026, 9, 20))
        self.assertTrue(verification["required"])
        self.assertIn("runtime_version_changed_reference_only", reasons)
        with mock.patch.object(search.shadow_gate, "runtime_binding", return_value={"manifest_sha256": "a" * 64}):
            self.assertFalse(retrieve._live_verification(metadata, dt.date(2026, 9, 20))[0]["required"])


if __name__ == "__main__":
    unittest.main()
