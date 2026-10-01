from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from tests.test_studio_memory_write import AiluWriteSandbox, MEMORYCTL, run
import agent_memory_claim as memory_claim
import agent_memory_intent as intent
import agent_memory_write as writer


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


class CommittedContentUpdateRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.box = AiluWriteSandbox()
        self.root = self.box.root
        self.repo = self.box.git_root
        self.vault = self.box.vault
        self.runtime = self.box.runtime
        self.state_db = self.box.state_db
        self.session = "codex-original-recovery-session"
        self.exit_stack = contextlib.ExitStack()
        for module in (intent, writer.write_intent):
            self.exit_stack.enter_context(
                mock.patch.object(module, "VAULT_ROOT", self.vault)
            )
            self.exit_stack.enter_context(
                mock.patch.object(module, "GIT_ROOT", self.repo)
            )
            self.exit_stack.enter_context(
                mock.patch.object(module, "STATE_DB", self.state_db)
            )
            self.exit_stack.enter_context(
                mock.patch.object(
                    module,
                    "assert_runtime_ready",
                    return_value={"ready": True},
                )
            )
        self.exit_stack.enter_context(
            mock.patch.object(memory_claim, "VAULT_ROOT", self.vault)
        )
        self.exit_stack.enter_context(
            mock.patch.object(memory_claim, "GIT_ROOT", self.repo)
        )
        self.exit_stack.enter_context(
            mock.patch.object(memory_claim, "STATE_DB", self.state_db)
        )
        self.exit_stack.enter_context(
            mock.patch.object(
                memory_claim,
                "assert_runtime_ready",
                return_value={"ready": True},
            )
        )
        self.exit_stack.enter_context(mock.patch.object(writer, "ACTOR", "codex"))
        self.exit_stack.enter_context(
            mock.patch.object(writer, "CONFIG_ROOT", self.runtime)
        )
        self.exit_stack.enter_context(
            mock.patch.object(
                writer,
                "WRITE_LOCK_PATH",
                self.runtime / "locks" / "closeout.lock",
            )
        )
        self.exit_stack.enter_context(
            mock.patch.object(writer.memory_index, "VAULT_ROOT", self.vault)
        )

    def tearDown(self) -> None:
        self.exit_stack.close()
        self.box.close()

    @staticmethod
    def markdown(
        title: str,
        body: str,
        *,
        memory_id: str,
        action_sensitive: bool = False,
    ) -> str:
        fact_fields = (
            "fact_key: recovery.add\n"
            "valid_from: 2026-08-25\n"
            if action_sensitive
            else ""
        )
        return (
            "---\n"
            f"memory_id: {memory_id}\n"
            "memory_type: project\n"
            "track: project\n"
            "project_id: recovery-project\n"
            "app_id: recovery-app\n"
            "agent_scope: shared\n"
            "status: active\n"
            "created_by: codex\n"
            "last_updated_by: codex\n"
            "sensitivity: normal\n"
            f"risk_class: {'action_sensitive' if action_sensitive else 'ordinary'}\n"
            "temporal_policy: reviewable\n"
            "verified_at: 2026-08-25\n"
            "review_after_days: 90\n"
            f"{fact_fields}"
            "---\n\n"
            f"# {title}\n\n{body}\n"
        )

    def seed(
        self,
        action: str,
        *,
        history_drift: bool = False,
    ) -> tuple[Path, dict[str, object], dict[str, object]]:
        target = self.vault / "项目" / f"Recovery{action}.md"
        canonical = intent.canonical_target(target)
        memory_id = writer.memory_index.memory_identity(
            canonical.rel_path,
            {},
        )[0]
        if action == "UPDATE":
            target.write_text(
                self.markdown(
                    "Recovery UPDATE",
                    "Original bytes.",
                    memory_id=memory_id,
                    action_sensitive=False,
                ),
                encoding="utf-8",
            )
            git(self.repo, "add", f"AgentMemory/项目/{target.name}")
            git(self.repo, "commit", "-qm", "add update base")
        base_exists, base_digest = intent._read_target(canonical)
        base_git_head = intent.current_git_head(required=True)
        read_token = writer._read_token(
            canonical,
            app_id="recovery-app",
            project_id="recovery-project",
            exists=base_exists,
            digest=base_digest,
            git_head=base_git_head,
            raw_session_id=self.session,
        )
        if action == "ADD":
            memory_id = writer._generated_memory_id(read_token)
        proposal = self.markdown(
            f"Recovery {action}",
            f"Exact committed {action.lower()} proposal.",
            memory_id=memory_id,
            action_sensitive=action == "ADD",
        )
        created = intent.create_intent(
            actor="codex",
            raw_session_id=self.session,
            target=target,
            proposal_text=proposal,
            approval_required=True,
            source_class="local_verified",
            knowledge_kind="fact" if action == "ADD" else "rule",
            asserted_by="codex",
            evidence_ref_sha256="e" * 64,
            reconcile_action=action,
            operation="content_update",
            read_token=read_token,
            scope_app_id="recovery-app",
            scope_project_id="recovery-project",
        )
        approval_reference = f"task:{action.lower()}-confirmed"
        intent.approve_intent(
            str(created["intent_id"]),
            actor="codex",
            raw_session_id=self.session,
            target=target,
            proposal_raw_sha256=str(created["proposal_raw_sha256"]),
            proposal_canonical_sha256=str(
                created["proposal_canonical_sha256"]
            ),
            approved_by="codex",
            approval_ref=approval_reference,
        )
        bound = intent.bind_claim(
            str(created["intent_id"]),
            actor="codex",
            raw_session_id=self.session,
            claim_path=target,
            claim_ref=f"claim:{action.lower()}",
            fencing_token=int(created["fencing_token"]),
        )
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        with contextlib.closing(
            sqlite3.connect(self.state_db)
        ) as connection, connection:
            connection.execute(
                "INSERT INTO memory_session_claims ("
                "session_hash, actor, path, rel_path, status, claimed_at, "
                "updated_at, completed_at, intent_id, target_key, "
                "fencing_token, claim_kind"
                ") VALUES (?, 'codex', ?, ?, 'active', ?, ?, NULL, ?, ?, ?, 'intent')",
                (
                    intent.session_hash(self.session),
                    str(canonical.path),
                    canonical.rel_path,
                    now,
                    now,
                    str(created["intent_id"]),
                    canonical.target_key,
                    int(created["fencing_token"]),
                ),
            )
        target.write_text(proposal, encoding="utf-8")
        validated = intent.validate_closeout(
            str(created["intent_id"]),
            actor="codex",
            raw_session_id=self.session,
            target=target,
            require_bound=True,
            mutate=True,
        )
        self.assertTrue(validated["ok"])
        self.assertFalse(validated["early_commit"])
        if history_drift:
            target.write_text(
                self.markdown(
                    f"Recovery {action}",
                    "Intervening wrong bytes.",
                    memory_id=memory_id,
                    action_sensitive=action == "ADD",
                ),
                encoding="utf-8",
            )
            git(self.repo, "add", f"AgentMemory/项目/{target.name}")
            git(self.repo, "commit", "-qm", "intervening wrong target")
            target.write_text(proposal, encoding="utf-8")
        git(self.repo, "add", f"AgentMemory/项目/{target.name}")
        git(self.repo, "commit", "-qm", f"external exact {action.lower()} proposal")
        with contextlib.closing(
            sqlite3.connect(self.state_db)
        ) as connection, connection:
            connection.execute(
                "UPDATE memory_write_intents SET expires_at=? WHERE intent_id=?",
                ("2000-01-01T00:00:00+00:00", str(created["intent_id"])),
            )
        request: dict[str, object] = {
            "schema_version": 2,
            "proposal_id": str(created["intent_id"]),
            "fencing_token": int(created["fencing_token"]),
            "target_relative_path": canonical.rel_path,
            "proposal_markdown": proposal,
            "proposal_raw_sha256": str(created["proposal_raw_sha256"]),
            "proposal_canonical_sha256": str(
                created["proposal_canonical_sha256"]
            ),
            "confirmed_by": "codex",
            "confirmation_reference": approval_reference,
        }
        return target, request, bound

    def invoke(
        self,
        request: dict[str, object],
        *,
        session: str | None = None,
    ) -> dict[str, object]:
        with mock.patch.object(
            writer,
            "_intent_scope_binding",
            return_value=("recovery-app", "recovery-project"),
        ), mock.patch.object(
            writer,
            "_validate_writer_markdown",
        ), mock.patch.object(
            writer,
            "_validate_write_temporal_gate",
        ), mock.patch.object(
            writer,
            "_validate_temporal_transition",
        ), mock.patch.object(
            writer,
            "_content_update_status",
        ):
            return writer._apply_locked(
                request,
                raw_session_id=session or self.session,
            )

    def apply_cli(
        self,
        request: dict[str, object],
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        completed = run(
            [
                sys.executable,
                "-I",
                "-S",
                str(MEMORYCTL),
                "--actor",
                "codex",
                "write",
                "apply",
                "--json",
                "--lock-timeout",
                "10",
                "--closeout-timeout",
                "90",
            ],
            cwd=REPO_ROOT,
            env=self.box.env(self.session),
            input_text=json.dumps(request, ensure_ascii=False),
            timeout=120,
        )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"non-json apply output (rc={completed.returncode}):\n"
                f"stdout={completed.stdout}\nstderr={completed.stderr}"
            ) from exc
        self.assertIsInstance(payload, dict)
        return completed, payload

    def assert_real_closeout_recovery(self, action: str) -> None:
        target, request, _bound = self.seed(action)
        proposal_id = str(request["proposal_id"])
        proposal_commit = git(self.repo, "rev-parse", "HEAD")
        proposal_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()

        completed, applied = self.apply_cli(request)
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr + completed.stdout,
        )
        self.assertEqual(applied["status"], "applied")
        self.assertTrue(applied["idempotent"])
        self.assertEqual(applied["git_commit"], proposal_commit)
        self.assertEqual(
            hashlib.sha256(
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.repo),
                        "show",
                        f"{proposal_commit}:AgentMemory/{request['target_relative_path']}",
                    ],
                    capture_output=True,
                    check=True,
                ).stdout
            ).hexdigest(),
            proposal_sha256,
        )

        with contextlib.closing(sqlite3.connect(self.state_db)) as connection:
            intent_row = connection.execute(
                "SELECT status, reason_code FROM memory_write_intents "
                "WHERE intent_id=?",
                (proposal_id,),
            ).fetchone()
            receipt = connection.execute(
                "SELECT outcome, reason_code, git_commit, final_raw_sha256, "
                "fencing_token FROM memory_write_receipts WHERE intent_id=?",
                (proposal_id,),
            ).fetchone()
            claim = connection.execute(
                "SELECT status, completed_at FROM memory_session_claims "
                "WHERE intent_id=?",
                (proposal_id,),
            ).fetchone()
            active_claims = connection.execute(
                "SELECT COUNT(*) FROM memory_session_claims "
                "WHERE intent_id=? AND status='active'",
                (proposal_id,),
            ).fetchone()[0]
            observation = connection.execute(
                "SELECT sha256, actor, session_hash, intent_id, "
                "fencing_token, git_commit FROM memory_file_observations "
                "WHERE rel_path=?",
                (str(request["target_relative_path"]),),
            ).fetchone()
            parity = tuple(
                connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE rel_path=?",
                    (str(request["target_relative_path"]),),
                ).fetchone()[0]
                for table in (
                    "memory_docs",
                    "memory_fts_unicode",
                    "memory_fts_trigram",
                )
            )
            receipt_count = connection.execute(
                "SELECT COUNT(*) FROM memory_write_receipts WHERE intent_id=?",
                (proposal_id,),
            ).fetchone()[0]

        self.assertEqual(
            intent_row,
            ("completed", intent.EXPIRED_VALIDATED_RECOVERY_COMPLETED_REASON),
        )
        self.assertEqual(
            receipt,
            (
                "completed",
                intent.EXPIRED_VALIDATED_RECOVERY_COMPLETED_REASON,
                proposal_commit,
                proposal_sha256,
                int(request["fencing_token"]),
            ),
        )
        self.assertEqual(active_claims, 0)
        self.assertEqual(claim[0], "completed")
        self.assertTrue(claim[1])
        self.assertEqual(
            observation,
            (
                proposal_sha256,
                "codex",
                intent.session_hash(self.session),
                proposal_id,
                int(request["fencing_token"]),
                proposal_commit,
            ),
        )
        self.assertEqual(parity, (1, 1, 1))
        generated_index = (self.vault / "INDEX.md").read_text(encoding="utf-8")
        self.assertIn(str(request["target_relative_path"]), generated_index)
        self.assertEqual(
            git(
                self.repo,
                "status",
                "--porcelain",
                "--",
                "AgentMemory/INDEX.md",
                f"AgentMemory/{request['target_relative_path']}",
            ),
            "",
        )

        retried, retry_payload = self.apply_cli(request)
        self.assertEqual(
            retried.returncode,
            0,
            retried.stderr + retried.stdout,
        )
        self.assertEqual(retry_payload["status"], "applied")
        self.assertTrue(retry_payload["idempotent"])
        self.assertEqual(retry_payload["receipt_id"], applied["receipt_id"])
        self.assertEqual(retry_payload["git_commit"], proposal_commit)
        with contextlib.closing(sqlite3.connect(self.state_db)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM memory_write_receipts WHERE intent_id=?",
                    (proposal_id,),
                ).fetchone()[0],
                receipt_count,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM memory_session_claims "
                    "WHERE intent_id=? AND status='active'",
                    (proposal_id,),
                ).fetchone()[0],
                0,
            )

    def test_add_recovers_through_real_closeout_and_retry_is_idempotent(self) -> None:
        self.assert_real_closeout_recovery("ADD")

    def test_update_recovers_through_real_closeout_and_retry_is_idempotent(self) -> None:
        self.assert_real_closeout_recovery("UPDATE")

    def test_wrong_session_cannot_recover(self) -> None:
        _target, request, _bound = self.seed("ADD")
        with self.assertRaises(writer.MemoryWriteError) as raised:
            self.invoke(request, session="different-codex-session")
        self.assertEqual(raised.exception.reason_code, "INTENT_SESSION_MISMATCH")

    def test_confirmation_and_durable_approval_binding_must_match(self) -> None:
        _target, request, _bound = self.seed("UPDATE")
        wrong_confirmation = {
            **request,
            "confirmation_reference": "task:different-confirmation",
        }
        with self.assertRaises(writer.MemoryWriteError) as wrong_reference:
            self.invoke(wrong_confirmation)
        self.assertEqual(
            wrong_reference.exception.reason_code,
            "APPROVAL_ALREADY_BOUND",
        )
        with contextlib.closing(
            sqlite3.connect(self.state_db)
        ) as connection, connection:
            connection.execute(
                "UPDATE memory_write_intents SET approval_binding_sha256=? "
                "WHERE intent_id=?",
                ("0" * 64, str(request["proposal_id"])),
            )
        with self.assertRaises(writer.MemoryWriteError) as binding_drift:
            self.invoke(request)
        self.assertEqual(
            binding_drift.exception.reason_code,
            "EXPIRED_VALIDATED_RECOVERY_BINDING_CHANGED",
        )

    def test_target_drift_cannot_recover(self) -> None:
        target, request, _bound = self.seed("ADD")
        target.write_text(str(request["proposal_markdown"]) + "drift\n", encoding="utf-8")
        with self.assertRaises(writer.MemoryWriteError) as target_drift:
            self.invoke(request)
        self.assertIn(
            target_drift.exception.reason_code,
            {
                "EXPIRED_VALIDATED_RECOVERY_TARGET_DRIFT",
                "EXPIRED_VALIDATED_RECOVERY_WORKTREE_DIRTY",
            },
        )

    def test_changed_then_restored_history_cannot_recover(self) -> None:
        _target, history_request, _bound = self.seed(
            "UPDATE",
            history_drift=True,
        )
        with self.assertRaises(writer.MemoryWriteError) as history_drift:
            self.invoke(history_request)
        self.assertEqual(
            history_drift.exception.reason_code,
            "EXPIRED_VALIDATED_RECOVERY_TARGET_HISTORY_CHANGED",
        )

    def test_newer_fence_cannot_recover(self) -> None:
        _target, request, bound = self.seed("ADD")
        with contextlib.closing(
            sqlite3.connect(self.state_db)
        ) as connection, connection:
            connection.execute(
                "UPDATE memory_path_fences SET last_fence=last_fence+1 "
                "WHERE target_key=?",
                (str(bound["target_key"]),),
            )
        with self.assertRaises(writer.MemoryWriteError) as newer_fence:
            self.invoke(request)
        self.assertEqual(newer_fence.exception.reason_code, "LEASE_FENCED")

    def test_changed_claim_projection_cannot_recover(self) -> None:
        _target, claim_request, _bound = self.seed("UPDATE")
        with contextlib.closing(
            sqlite3.connect(self.state_db)
        ) as connection, connection:
            connection.execute(
                "UPDATE memory_session_claims SET fencing_token=fencing_token+1 "
                "WHERE intent_id=? AND status='active'",
                (str(claim_request["proposal_id"]),),
            )
        with self.assertRaises(writer.MemoryWriteError) as newer_claim:
            self.invoke(claim_request)
        self.assertEqual(
            newer_claim.exception.reason_code,
            "EXPIRED_VALIDATED_RECOVERY_CLAIM_CHANGED",
        )


if __name__ == "__main__":
    unittest.main()
