from __future__ import annotations

import contextlib
import hashlib
import sqlite3
import unittest
from unittest import mock

from tests import test_write_gateway_recovery as fixture
import agent_memory_closeout as closeout
import agent_memory_migrate as migrate


class CommittedRecoveryMigrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.CommittedContentUpdateRecoveryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for module, key, value in (
            (migrate, "STATE_DB", self.fixture.state_db),
            (closeout, "STATE_DB", self.fixture.state_db),
            (closeout, "VAULT_ROOT", self.fixture.vault),
            (closeout, "REPO_ROOT", self.fixture.repo),
        ):
            self.stack.enter_context(mock.patch.object(module, key, value))

    def seed(self, **kwargs):
        return self.fixture.seed("UPDATE", **kwargs)

    def plan(self):
        with contextlib.closing(migrate.connect(read_only=True)) as conn:
            return migrate.committed_recovery_plan(conn)

    def reviewed(self):
        plan = self.plan()
        self.assertTrue(plan["ok"], plan)
        self.assertEqual(len(plan["plan"]["entries"]), 1)
        return {**plan, "approval": {
            "approved": True, "reason_code": "REPAIR_COMMITTED_CLOSEOUT_LEDGER",
            "authorization_ref_sha256": hashlib.sha256(b"explicit maintenance approval").hexdigest(),
        }}

    def apply(self, document, name="recovery.sqlite"):
        with contextlib.closing(migrate.connect(read_only=False)) as conn:
            return migrate.apply_migration(
                conn, backup_path=self.fixture.root / name,
                committed_recovery_document=document,
            )

    def sql(self, query, values=()):
        with contextlib.closing(sqlite3.connect(self.fixture.state_db)) as conn, conn:
            return conn.execute(query, values).fetchall()

    def test_backed_up_exact_recovery_preserves_bytes_and_approval_and_is_idempotent(self):
        target, _, _ = self.seed()
        contents = target.read_bytes()
        approval = self.sql("SELECT approval_binding_sha256,evidence_ref_sha256,session_hash FROM memory_write_intents")
        document = self.reviewed()
        result = self.apply(document)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["committed_recovery"]["recovered"], 1)
        self.assertEqual(target.read_bytes(), contents)
        self.assertEqual(approval, self.sql("SELECT approval_binding_sha256,evidence_ref_sha256,session_hash FROM memory_write_receipts"))
        self.assertEqual(self.sql("SELECT status FROM memory_session_claims"), [("completed",)])
        self.assertEqual(self.sql("SELECT sha256 FROM memory_file_observations WHERE intent_id<>''"), [(hashlib.sha256(contents).hexdigest(),)])
        with sqlite3.connect(self.fixture.root / "recovery.sqlite") as backup:
            self.assertEqual(backup.execute("SELECT status FROM memory_write_intents").fetchall(), [("validated",)])
        repeat = self.apply(document, "repeat.sqlite")
        self.assertTrue(repeat["committed_recovery"]["idempotent"])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM memory_write_receipts"), [(1,)])

    def test_plan_rejects_intervening_history_even_if_current_bytes_match(self):
        self.seed(history_drift=True)
        self.assertFalse(self.plan()["ok"])

    def test_reviewed_plan_does_not_authorize_later_content_or_head_changes(self):
        target, _, _ = self.seed()
        document = self.reviewed()
        target.write_text(target.read_text() + "\nUnreviewed change.\n")
        with self.assertRaisesRegex(ValueError, "COMMITTED_RECOVERY_PLAN_CHANGED"):
            self.apply(document)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM memory_write_receipts"), [(0,)])

    def test_new_fence_or_missing_approval_is_not_recoverable(self):
        self.seed()
        self.sql("UPDATE memory_path_fences SET last_fence=last_fence+1")
        self.assertFalse(self.plan()["ok"])
        self.sql("UPDATE memory_path_fences SET last_fence=last_fence-1")
        self.sql("UPDATE memory_write_intents SET approval_binding_sha256=''")
        self.assertFalse(self.plan()["ok"])

    def test_live_lease_is_never_taken_over(self):
        self.seed()
        self.sql("UPDATE memory_write_intents SET expires_at='2999-01-01T00:00:00+00:00'")
        self.assertEqual(self.plan()["plan"]["entries"], [])

    def test_apply_requires_explicit_maintenance_approval(self):
        self.seed()
        document = self.reviewed()
        document.pop("approval")
        with self.assertRaisesRegex(ValueError, "COMMITTED_RECOVERY_APPROVAL_REQUIRED"):
            self.apply(document)
        self.assertEqual(self.sql("SELECT status FROM memory_write_intents"), [("validated",)])

    def test_content_race_rolls_back_all_ledger_changes(self):
        self.seed()
        document = self.reviewed()
        # A changed Git HEAD on the final check must roll back every projection.
        original = migrate.intent.current_git_head
        calls = 0
        def raced_head(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs) if calls <= 2 else "f" * 40
        with mock.patch.object(migrate.intent, "current_git_head", side_effect=raced_head):
            with self.assertRaisesRegex(ValueError, "COMMITTED_RECOVERY_HEAD_CHANGED"):
                self.apply(document)
        self.assertEqual(self.sql("SELECT status FROM memory_write_intents"), [("validated",)])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM memory_write_receipts"), [(0,)])


if __name__ == "__main__":
    unittest.main()
