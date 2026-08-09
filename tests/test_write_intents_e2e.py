from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
MEMORYCTL = SCRIPTS / "memoryctl"


def run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int = 45,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        capture_output=True,
        timeout=20,
        check=True,
    )
    return completed.stdout.strip()


def toml_string(value: str | Path) -> str:
    return json.dumps(str(value), ensure_ascii=False)


class IntentSandbox:
    """Small real Git/vault/runtime used only by subprocess E2E tests."""

    def __init__(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name).resolve()
        self.git_root = self.root / "repo"
        self.vault = self.git_root / "AgentMemory"
        self.runtime = self.root / "runtime"
        self.state_db = self.runtime / "state.sqlite"
        self.config = self.runtime / "config" / "agent-memory.toml"
        self.git_root.mkdir(parents=True)
        self.runtime.mkdir(parents=True)
        self._create_minimal_vault()
        self._init_git()
        self._write_config()
        self.base_env = os.environ.copy()
        self.base_env["AGENT_MEMORY_CONFIG_FILE"] = str(self.config)
        for key in (
            "AGENT_MEMORY_SESSION_ID",
            "CODEX_THREAD_ID",
            "CLAUDE_SESSION_ID",
            "CLAUDE_CODE_SESSION_ID",
        ):
            self.base_env.pop(key, None)
        self._initialize_state()

    def close(self) -> None:
        self.tempdir.cleanup()

    def _memory_text(self, title: str, body: str = "Baseline.") -> str:
        return (
            "---\n"
            "memory_type: workflow\n"
            "track: workflow\n"
            "status: active\n"
            "---\n\n"
            f"# {title}\n\n"
            f"{body}\n"
        )

    def _create_minimal_vault(self) -> None:
        required_dirs = (
            self.vault / "用户记忆",
            self.vault / "工作流",
            self.vault / "agent" / "case-candidates",
            self.vault / "agent" / "cases",
            self.vault / "agent" / "skill-candidates",
        )
        for path in required_dirs:
            path.mkdir(parents=True, exist_ok=True)

        plain_files = {
            self.vault / "AGENTS.md": "# Test Agent Memory\n",
            self.vault / "INDEX.md": "# Test Index\n",
            self.vault / "用户记忆" / "README.md": "# User Memory\n",
            self.vault / "工作流" / "Agent记忆字段规范.md": self._memory_text("Field schema"),
            self.vault / "agent" / "case-candidates" / "README.md": "# Candidates\n",
            self.vault / "agent" / "cases" / "README.md": "# Cases\n",
            self.vault / "agent" / "skill-candidates" / "README.md": "# Skills\n",
        }
        frontmatter_files = {
            self.vault / "用户记忆" / "偏好与边界.md": "user_preference",
            self.vault / "用户记忆" / "长期画像.md": "user_profile",
            self.vault / "agent" / "case-candidates" / "_模板-AgentCase候选.md": "agent_case_candidate",
            self.vault / "agent" / "cases" / "_模板-AgentCase正式记忆.md": "agent_case",
            self.vault / "agent" / "skill-candidates" / "_模板-Skill候选.md": "skill_candidate",
        }
        for path, text in plain_files.items():
            path.write_text(text, encoding="utf-8")
        for path, memory_type in frontmatter_files.items():
            path.write_text(
                f"---\nmemory_type: {memory_type}\nstatus: active\n---\n\n# {path.stem}\n",
                encoding="utf-8",
            )

        for stem in (
            "Protected",
            "WrongA",
            "WrongB",
            "Stale",
            "Early",
            "Approval",
            "Concurrent",
            "Format",
            "Mismatch",
            "Orphan",
        ):
            (self.vault / "工作流" / f"{stem}.md").write_text(
                self._memory_text(stem),
                encoding="utf-8",
            )

    def _init_git(self) -> None:
        git(self.git_root, "init", "-q")
        git(self.git_root, "config", "user.name", "Write Intent E2E")
        git(self.git_root, "config", "user.email", "intent-e2e@example.invalid")
        git(self.git_root, "add", "AgentMemory")
        git(self.git_root, "commit", "-qm", "baseline")

    def _write_config(self) -> None:
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text(
            "\n".join(
                [
                    f"memory_root = {toml_string(self.vault)}",
                    f"git_root = {toml_string(self.git_root)}",
                    f"config_root = {toml_string(self.runtime)}",
                    f"state_db = {toml_string(self.state_db)}",
                    f"closeout_log = {toml_string(self.runtime / 'logs' / 'closeout.jsonl')}",
                    f"audit_run_log = {toml_string(self.runtime / 'logs' / 'audit_runs.jsonl')}",
                    f"python = {toml_string(sys.executable)}",
                    "",
                    "[semantic_retrieval]",
                    "enabled = false",
                    f"python = {toml_string(sys.executable)}",
                    "",
                    "[write_intents]",
                    "enabled = true",
                    'enforcement = "enforce"',
                    "ttl_hours = 24",
                    "max_proposal_bytes = 1048576",
                    "max_target_bytes = 1048576",
                    'protected_paths = ["工作流/*.md", "用户记忆/偏好与边界.md"]',
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    def _initialize_state(self) -> None:
        for script in ("agent_memory_evolution.py", "agent_memory_index.py"):
            completed = run(
                [sys.executable, str(SCRIPTS / script), "--init", "--scan"],
                cwd=REPO_ROOT,
                env=self.base_env,
            )
            if completed.returncode != 0:
                raise AssertionError(completed.stderr + completed.stdout)

    def env(self, actor: str, session: str) -> dict[str, str]:
        payload = self.base_env.copy()
        if actor == "codex":
            payload["CODEX_THREAD_ID"] = session
        elif actor == "claude":
            payload["CLAUDE_SESSION_ID"] = session
        else:
            payload["AGENT_MEMORY_SESSION_ID"] = session
        return payload

    def ctl_command(self, actor: str, command: str, *args: str) -> list[str]:
        return [sys.executable, str(MEMORYCTL), "--actor", actor, command, *args]

    def ctl(
        self,
        actor: str,
        session: str,
        command: str,
        *args: str,
        timeout: int = 45,
    ) -> subprocess.CompletedProcess[str]:
        return run(
            self.ctl_command(actor, command, *args),
            cwd=REPO_ROOT,
            env=self.env(actor, session),
            timeout=timeout,
        )

    def json_payload(self, completed: subprocess.CompletedProcess[str]) -> dict[str, object]:
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"non-json output (rc={completed.returncode}):\nstdout={completed.stdout}\nstderr={completed.stderr}"
            ) from exc
        if not isinstance(payload, dict):
            raise AssertionError(f"expected object, got: {payload!r}")
        return payload

    def proposal(self, name: str, text: str, *, raw: bytes | None = None) -> Path:
        path = self.root / "proposals" / f"{name}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        if raw is None:
            path.write_text(text, encoding="utf-8")
        else:
            path.write_bytes(raw)
        return path

    def create_intent(
        self,
        *,
        actor: str,
        session: str,
        target: Path,
        proposal: Path,
        approval_required: bool = False,
        knowledge_kind: str = "fact",
        evidence_ref_sha256: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        args = [
            "create",
            "--target",
            str(target),
            "--proposal-file",
            str(proposal),
            "--source-class",
            "user_direct",
            "--knowledge-kind",
            knowledge_kind,
            "--asserted-by",
            "user",
        ]
        if not approval_required:
            args.append("--no-approval-required")
        if evidence_ref_sha256:
            args.extend(["--evidence-ref-sha256", evidence_ref_sha256])
        args.append("--json")
        completed = self.ctl(actor, session, "intent", *args)
        return completed, self.json_payload(completed)

    def claim(
        self,
        *,
        actor: str,
        session: str,
        target: Path,
        intent_id: str = "",
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        args = ["--file", str(target)]
        if intent_id:
            args.extend(["--intent-id", intent_id])
        args.append("--json")
        completed = self.ctl(actor, session, "claim", *args)
        return completed, self.json_payload(completed)

    def closeout(
        self,
        *,
        actor: str,
        session: str,
        global_mode: bool = False,
        explicit_session: bool = False,
        dry_run: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        args = [
            "--skip-zvec",
            "--no-zvec",
            "--skip-audit",
            "--trigger",
            "test",
            "--lock-timeout",
            "10",
            "--json",
        ]
        if global_mode:
            args.insert(0, "--global")
        if explicit_session:
            args.extend(["--session-id", session])
        if dry_run:
            args.append("--dry-run")
        completed = self.ctl(actor, session, "closeout", *args, timeout=90)
        return completed, self.json_payload(completed)


class WriteIntentEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.box = IntentSandbox()

    def tearDown(self) -> None:
        self.box.close()

    def test_expired_exact_early_commit_can_be_recovered_as_audited_observation(self) -> None:
        session = "codex-historical-observation"
        target = self.box.vault / "用户记忆" / "偏好与边界.md"
        proposal_text = target.read_text(encoding="utf-8") + "\n- User-authorized preference.\n"
        proposal = self.box.proposal(
            "historical-observation",
            "",
            raw=proposal_text.replace("\n", "\r\n").encode("utf-8"),
        )
        created, intent = self.box.create_intent(
            actor="codex",
            session=session,
            target=target,
            proposal=proposal,
            knowledge_kind="preference",
            evidence_ref_sha256="d" * 64,
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        intent_id = str(intent["intent_id"])
        claimed, _ = self.box.claim(
            actor="codex",
            session=session,
            target=target,
            intent_id=intent_id,
        )
        self.assertEqual(claimed.returncode, 0, claimed.stderr + claimed.stdout)
        target.write_bytes(proposal.read_bytes())
        git(self.box.git_root, "add", "AgentMemory/用户记忆/偏好与边界.md")
        git(self.box.git_root, "commit", "-qm", "external authorized preference commit")

        validated = self.box.ctl(
            "codex",
            session,
            "intent",
            "validate",
            "--intent-id",
            intent_id,
            "--target",
            str(target),
            "--json",
        )
        self.assertEqual(validated.returncode, 0, validated.stderr + validated.stdout)
        self.assertTrue(self.box.json_payload(validated)["early_commit"])
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            conn.execute(
                "UPDATE memory_write_intents SET expires_at=validated_at "
                "WHERE intent_id=?",
                (intent_id,),
            )
            conn.commit()
        expired = self.box.ctl("codex", session, "intent", "expire", "--apply", "--json")
        self.assertEqual(expired.returncode, 0, expired.stderr + expired.stdout)
        self.assertEqual(self.box.json_payload(expired)["applied"], 1)

        observe_args = (
            "--file",
            str(target),
            "--intent-id",
            intent_id,
            "--evidence-ref",
            "verified-original-user-authorization",
            "--confirm-user-authorized",
            "--json",
        )
        blocked = self.box.ctl("human", "human-maintenance", "observe-committed", *observe_args)
        self.assertEqual(blocked.returncode, 2, blocked.stderr + blocked.stdout)
        self.assertIn("active intent or session claim", self.box.json_payload(blocked)["error"])

        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            conn.execute(
                "UPDATE memory_session_claims SET status='expired', completed_at=updated_at "
                "WHERE path=? AND status='active'",
                (str(target),),
            )
            conn.commit()
        preview = self.box.ctl("human", "human-maintenance", "observe-committed", *observe_args)
        self.assertEqual(preview.returncode, 0, preview.stderr + preview.stdout)
        self.assertTrue(self.box.json_payload(preview)["preview"])
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            count_before = conn.execute("SELECT COUNT(*) FROM memory_committed_observations").fetchone()[0]
        self.assertEqual(count_before, 0)

        race_script = f"""
import sys
sys.path.insert(0, {str(SCRIPTS)!r})
import agent_memory_claim as claim
observation = claim.validate_committed_observation(
    actor='human',
    target_file={str(target)!r},
    intent_id={intent_id!r},
    evidence_ref='verified-original-user-authorization',
    user_authorized=True,
)
with claim.connect() as conn:
    conn.execute('BEGIN IMMEDIATE')
    conn.execute(
        \"\"\"INSERT INTO memory_session_claims (
          session_hash, actor, path, rel_path, status, claimed_at, updated_at, completed_at, intent_id
        ) VALUES (?, 'codex', ?, ?, 'active', ?, ?, NULL, '')\"\"\",
        ('1' * 16, {str(target)!r}, '用户记忆/偏好与边界.md', claim.utc_now(), claim.utc_now()),
    )
    conn.commit()
try:
    claim._store_committed_observation(observation)
except ValueError as exc:
    print(str(exc))
    raise SystemExit(0)
raise SystemExit(3)
"""
        raced = run(
            [sys.executable, "-c", race_script],
            cwd=REPO_ROOT,
            env=self.box.env("human", "human-maintenance"),
        )
        self.assertEqual(raced.returncode, 0, raced.stderr + raced.stdout)
        self.assertIn("gained an active intent or session claim", raced.stdout)
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            conn.execute(
                "UPDATE memory_session_claims SET status='expired', completed_at=updated_at "
                "WHERE session_hash=? AND path=?",
                ("1" * 16, str(target)),
            )
            conn.commit()

        applied_args = (*observe_args[:-1], "--apply", "--json")
        applied = self.box.ctl("human", "human-maintenance", "observe-committed", *applied_args)
        self.assertEqual(applied.returncode, 0, applied.stderr + applied.stdout)
        applied_payload = self.box.json_payload(applied)
        self.assertEqual(applied_payload["applied"], 1)
        self.assertFalse(applied_payload["preview"])
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            audit = conn.execute(
                "SELECT actor, user_authorized, intent_id, proposal_commit, evidence_ref_sha256 "
                "FROM memory_committed_observations"
            ).fetchone()
            observed = conn.execute(
                "SELECT sha256, actor, session_hash FROM memory_file_observations WHERE path=?",
                (str(target),),
            ).fetchone()
        self.assertEqual(audit[0:3], ("human", 1, intent_id))
        self.assertEqual(audit[3], git(self.box.git_root, "log", "-1", "--format=%H", "--", "AgentMemory/用户记忆/偏好与边界.md"))
        self.assertEqual(
            audit[4],
            hashlib.sha256(b"verified-original-user-authorization").hexdigest(),
        )
        self.assertEqual(observed[1:], ("human", ""))

        repeated = self.box.ctl("human", "human-maintenance", "observe-committed", *applied_args)
        self.assertEqual(repeated.returncode, 0, repeated.stderr + repeated.stdout)
        self.assertEqual(self.box.json_payload(repeated)["applied"], 0)

        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            conn.execute(
                "UPDATE memory_write_receipts SET evidence_ref_sha256=? WHERE intent_id=?",
                ("f" * 64, intent_id),
            )
            conn.commit()
        corrupted = self.box.ctl("human", "human-maintenance", "observe-committed", *observe_args)
        self.assertEqual(corrupted.returncode, 2, corrupted.stderr + corrupted.stdout)
        self.assertIn("not eligible", self.box.json_payload(corrupted)["error"])

        proposal_commit = git(
            self.box.git_root,
            "log",
            "-1",
            "--format=%H",
            "--",
            "AgentMemory/用户记忆/偏好与边界.md",
        )
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            conn.execute(
                "UPDATE memory_write_receipts SET evidence_ref_sha256=?, base_git_head=? "
                "WHERE intent_id=?",
                ("d" * 64, proposal_commit, intent_id),
            )
            conn.execute(
                "UPDATE memory_write_intents SET base_git_head=? WHERE intent_id=?",
                (proposal_commit, intent_id),
            )
            conn.commit()
        equal_base = self.box.ctl("human", "human-maintenance", "observe-committed", *observe_args)
        self.assertEqual(equal_base.returncode, 2, equal_base.stderr + equal_base.stdout)
        self.assertIn("not eligible", self.box.json_payload(equal_base)["error"])

    def test_complete_dry_run_leaves_state_database_byte_identical(self) -> None:
        session = "codex-dry-run-readonly"
        target = self.box.vault / "工作流" / "Protected.md"
        proposal = self.box.proposal(
            "dry-run-readonly",
            self.box._memory_text("Protected", "dryrunreadonly94731"),
        )
        created, intent = self.box.create_intent(
            actor="codex",
            session=session,
            target=target,
            proposal=proposal,
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        claimed, _ = self.box.claim(
            actor="codex",
            session=session,
            target=target,
            intent_id=str(intent["intent_id"]),
        )
        self.assertEqual(claimed.returncode, 0, claimed.stderr + claimed.stdout)
        target.write_bytes(proposal.read_bytes())

        with contextlib.closing(sqlite3.connect(f"file:{self.box.state_db}?mode=ro", uri=True)) as conn, conn:
            schema_before = conn.execute(
                "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
            ).fetchall()
            counts_before = {
                name: conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                for (name,) in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            }
        before = {
            path.name: path.read_bytes()
            for path in self.box.runtime.glob("state.sqlite*")
            if path.is_file()
        }

        closed, payload = self.box.closeout(
            actor="codex",
            session=session,
            dry_run=True,
        )
        self.assertIn(closed.returncode, {0, 1}, closed.stderr + closed.stdout)
        self.assertNotEqual(payload["status"], "error", payload)

        after = {
            path.name: path.read_bytes()
            for path in self.box.runtime.glob("state.sqlite*")
            if path.is_file()
        }
        with contextlib.closing(sqlite3.connect(f"file:{self.box.state_db}?mode=ro", uri=True)) as conn, conn:
            schema_after = conn.execute(
                "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
            ).fetchall()
            counts_after = {
                name: conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                for (name,) in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            }
        self.assertEqual(before, after)
        self.assertEqual(schema_before, schema_after)
        self.assertEqual(counts_before, counts_after)

    def test_normal_prewrite_new_file_claim_before_edit_closeout_commit_and_receipt(self) -> None:
        session = "codex-normal-e2e"
        target = self.box.vault / "工作流" / "NewProtected.md"
        proposal_text = self.box._memory_text("New protected", "newflowe2e94731")
        proposal = self.box.proposal("normal", proposal_text)
        self.assertFalse(target.exists())

        prewrite = self.box.ctl(
            "codex",
            session,
            "prewrite",
            "newflowe2e94731",
            "--create-intent",
            "--target-file",
            str(target),
            "--proposal-file",
            str(proposal),
            "--source-class",
            "user_direct",
            "--knowledge-kind",
            "fact",
            "--asserted-by",
            "user",
            "--evidence-ref",
            "e2e:user-request",
            "--no-zvec",
            "--json",
        )
        prewrite_payload = self.box.json_payload(prewrite)
        self.assertEqual(prewrite.returncode, 0, prewrite.stderr + prewrite.stdout)
        self.assertEqual(prewrite_payload["recommended_action"], "ADD")
        intent = prewrite_payload["write_intent"]
        self.assertIsInstance(intent, dict)
        intent_id = str(intent["intent_id"])

        claimed, claim_payload = self.box.claim(
            actor="codex", session=session, target=target, intent_id=intent_id
        )
        self.assertEqual(claimed.returncode, 0, claimed.stderr + claimed.stdout)
        self.assertEqual(claim_payload["count"], 1)
        self.assertFalse(target.exists(), "new files must be claimable before the edit")

        target.write_bytes(proposal.read_bytes())
        closed, closeout_payload = self.box.closeout(actor="codex", session=session)
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        self.assertEqual(closeout_payload["status"], "ok")
        self.assertEqual(closeout_payload["processed_files"], ["工作流/NewProtected.md"])
        self.assertEqual(len(closeout_payload["write_intent_receipts"]), 1)

        head = git(self.box.git_root, "rev-parse", "HEAD")
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            intent_row = conn.execute(
                "SELECT status FROM memory_write_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            receipt = conn.execute(
                "SELECT outcome, git_commit FROM memory_write_receipts WHERE intent_id=?", (intent_id,)
            ).fetchone()
            claim_status = conn.execute(
                "SELECT status FROM memory_session_claims WHERE intent_id=?", (intent_id,)
            ).fetchone()
        self.assertEqual(intent_row, ("completed",))
        self.assertEqual(receipt, ("completed", head))
        self.assertEqual(claim_status, ("completed",))
        self.assertEqual(
            git(self.box.git_root, "show", f"{head}:AgentMemory/工作流/NewProtected.md"),
            proposal_text.rstrip("\n"),
        )

    def test_direct_protected_edit_without_prewrite_or_intent_is_rejected(self) -> None:
        session = "codex-direct-edit"
        target = self.box.vault / "工作流" / "Protected.md"
        target.write_text(self.box._memory_text("Protected", "direct unsafe edit"), encoding="utf-8")

        claimed, claim_payload = self.box.claim(actor="codex", session=session, target=target)
        self.assertEqual(claimed.returncode, 2, claimed.stderr + claimed.stdout)
        self.assertFalse(claim_payload["ok"])
        self.assertIn("protected memory requires", str(claim_payload["error"]))

        closed, payload = self.box.closeout(
            actor="codex", session=session, global_mode=True, explicit_session=True
        )
        self.assertEqual(closed.returncode, 2, closed.stderr + closed.stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["intent_error"], "PROTECTED_WRITE_WITHOUT_BOUND_INTENT")
        self.assertEqual(
            git(self.box.git_root, "-c", "core.quotepath=false", "status", "--short"),
            "M AgentMemory/工作流/Protected.md",
        )

    def test_intent_cannot_bind_to_a_different_path(self) -> None:
        session = "codex-path-mismatch"
        target = self.box.vault / "工作流" / "WrongA.md"
        wrong_target = self.box.vault / "工作流" / "WrongB.md"
        proposal = self.box.proposal("wrong-path", self.box._memory_text("WrongA", "updated"))
        created, intent = self.box.create_intent(
            actor="codex", session=session, target=target, proposal=proposal
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)

        claimed, payload = self.box.claim(
            actor="codex",
            session=session,
            target=wrong_target,
            intent_id=str(intent["intent_id"]),
        )
        self.assertEqual(claimed.returncode, 2, claimed.stderr + claimed.stdout)
        self.assertFalse(payload["ok"])
        self.assertIn("does not match", str(payload["error"]))
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM memory_session_claims WHERE intent_id=?",
                (str(intent["intent_id"]),),
            ).fetchone()[0]
            status = conn.execute(
                "SELECT status FROM memory_write_intents WHERE intent_id=?",
                (str(intent["intent_id"]),),
            ).fetchone()[0]
        self.assertEqual(count, 0)
        self.assertEqual(status, "pending")

    def test_stale_base_is_terminal_before_claim(self) -> None:
        session = "codex-stale-base"
        target = self.box.vault / "工作流" / "Stale.md"
        proposal = self.box.proposal("stale", self.box._memory_text("Stale", "proposed"))
        created, intent = self.box.create_intent(
            actor="codex", session=session, target=target, proposal=proposal
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        intent_id = str(intent["intent_id"])

        target.write_text(self.box._memory_text("Stale", "concurrent change"), encoding="utf-8")
        claimed, payload = self.box.claim(
            actor="codex", session=session, target=target, intent_id=intent_id
        )
        self.assertEqual(claimed.returncode, 2, claimed.stderr + claimed.stdout)
        self.assertFalse(payload["ok"])
        shown = self.box.ctl("codex", session, "intent", "show", "--intent-id", intent_id, "--json")
        shown_payload = self.box.json_payload(shown)
        self.assertEqual(shown_payload["intent"]["status"], "failed")
        self.assertEqual(shown_payload["receipt"]["reason_code"], "STALE_BASE")

    def test_early_external_commit_is_recovered_and_receipted(self) -> None:
        session = "codex-early-commit"
        target = self.box.vault / "工作流" / "Early.md"
        proposal = self.box.proposal("early", self.box._memory_text("Early", "externally committed"))
        created, intent = self.box.create_intent(
            actor="codex", session=session, target=target, proposal=proposal
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        intent_id = str(intent["intent_id"])
        claimed, _ = self.box.claim(
            actor="codex", session=session, target=target, intent_id=intent_id
        )
        self.assertEqual(claimed.returncode, 0, claimed.stderr + claimed.stdout)

        target.write_bytes(proposal.read_bytes())
        git(self.box.git_root, "add", "AgentMemory/工作流/Early.md")
        git(self.box.git_root, "commit", "-qm", "external obsidian backup")
        external_commit = git(self.box.git_root, "rev-parse", "HEAD")

        closed, payload = self.box.closeout(actor="codex", session=session)
        self.assertEqual(closed.returncode, 0, closed.stderr + closed.stdout)
        self.assertEqual(payload["status"], "ok")
        validation = payload["write_intent_validations"][0]
        self.assertTrue(validation["early_commit"])
        self.assertEqual(validation["proposal_commit"], external_commit)
        receipt = payload["write_intent_receipts"][0]
        self.assertEqual(receipt["outcome"], "completed")
        self.assertEqual(receipt["git_commit"], external_commit)
        self.assertEqual(git(self.box.git_root, "rev-parse", "HEAD"), external_commit)

    def test_approval_is_bound_to_intent_path_raw_canonical_hash_and_reference(self) -> None:
        session = "codex-approval"
        target = self.box.vault / "工作流" / "Approval.md"
        wrong_target = self.box.vault / "工作流" / "WrongB.md"
        proposal = self.box.proposal("approval", self.box._memory_text("Approval", "approved"))
        created, intent = self.box.create_intent(
            actor="codex",
            session=session,
            target=target,
            proposal=proposal,
            approval_required=True,
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        intent_id = str(intent["intent_id"])
        raw_hash = str(intent["proposal_raw_sha256"])
        canonical_hash = str(intent["proposal_canonical_sha256"])

        def approve(
            *,
            candidate_intent: str = intent_id,
            candidate_target: Path = target,
            candidate_raw: str = raw_hash,
            candidate_canonical: str = canonical_hash,
            approval_ref: str = "user-message:42",
        ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
            completed = self.box.ctl(
                "codex",
                session,
                "intent",
                "approve",
                "--intent-id",
                candidate_intent,
                "--target",
                str(candidate_target),
                "--proposal-raw-sha256",
                candidate_raw,
                "--proposal-canonical-sha256",
                candidate_canonical,
                "--approved-by",
                "user",
                "--approval-ref",
                approval_ref,
                "--json",
            )
            return completed, self.box.json_payload(completed)

        failures = (
            approve(candidate_intent="0" * 32),
            approve(candidate_target=wrong_target),
            approve(candidate_raw="0" * 64),
            approve(candidate_canonical="0" * 64),
        )
        expected_reasons = (
            "INTENT_NOT_FOUND",
            "APPROVAL_TARGET_MISMATCH",
            "APPROVAL_PROPOSAL_MISMATCH",
            "APPROVAL_PROPOSAL_MISMATCH",
        )
        self.assertEqual(len(failures), len(expected_reasons))
        for (completed, payload), reason in zip(failures, expected_reasons):
            self.assertEqual(completed.returncode, 2, completed.stderr + completed.stdout)
            self.assertEqual(payload["reason_code"], reason)

        approved, approved_payload = approve()
        self.assertEqual(approved.returncode, 0, approved.stderr + approved.stdout)
        self.assertEqual(approved_payload["status"], "approved")
        self.assertTrue(approved_payload["approval_binding_sha256"])
        self.assertTrue(approved_payload["approval_ref_sha256"])

        wrong_ref, wrong_ref_payload = approve(approval_ref="different-user-message")
        self.assertEqual(wrong_ref.returncode, 2, wrong_ref.stderr + wrong_ref.stdout)
        self.assertEqual(wrong_ref_payload["reason_code"], "APPROVAL_ALREADY_BOUND")

    def test_codex_and_claude_compete_for_one_canonical_target(self) -> None:
        target = self.box.vault / "工作流" / "Concurrent.md"
        proposal = self.box.proposal("concurrent", self.box._memory_text("Concurrent", "one owner"))
        base_args = (
            "create",
            "--target",
            str(target),
            "--proposal-file",
            str(proposal),
            "--no-approval-required",
            "--source-class",
            "user_direct",
            "--knowledge-kind",
            "fact",
            "--asserted-by",
            "user",
            "--json",
        )
        processes = []
        for actor, session in (("codex", "codex-race"), ("claude", "claude-race")):
            processes.append(
                subprocess.Popen(
                    self.box.ctl_command(actor, "intent", *base_args),
                    cwd=REPO_ROOT,
                    env=self.box.env(actor, session),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )
        outputs = [process.communicate(timeout=30) for process in processes]
        payloads = [json.loads(stdout) for stdout, _ in outputs]
        returncodes = [process.returncode for process in processes]
        self.assertEqual(sorted(returncodes), [0, 2], outputs)
        winner = payloads[returncodes.index(0)]
        loser = payloads[returncodes.index(2)]
        self.assertEqual(winner["target_key"], "工作流/concurrent.md")
        self.assertEqual(loser["reason_code"], "ACTIVE_TARGET_CONFLICT")
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            active = conn.execute(
                "SELECT COUNT(*) FROM memory_write_intents WHERE target_key=? "
                "AND status IN ('pending','approved','bound','validated')",
                ("工作流/concurrent.md",),
            ).fetchone()[0]
        self.assertEqual(active, 1)

    def test_format_only_passes_but_true_content_mismatch_is_receipted(self) -> None:
        session = "codex-content-validation"
        format_target = self.box.vault / "工作流" / "Format.md"
        format_raw = b"\xef\xbb\xbf# Format\r\n\r\nUpdated representation.\r\n"
        format_proposal = self.box.proposal("format", "", raw=format_raw)
        created, format_intent = self.box.create_intent(
            actor="codex", session=session, target=format_target, proposal=format_proposal
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        format_id = str(format_intent["intent_id"])
        claimed, _ = self.box.claim(
            actor="codex", session=session, target=format_target, intent_id=format_id
        )
        self.assertEqual(claimed.returncode, 0, claimed.stderr + claimed.stdout)
        format_target.write_text("# Format\n\nUpdated representation.\n", encoding="utf-8")
        validated = self.box.ctl(
            "codex",
            session,
            "intent",
            "validate",
            "--intent-id",
            format_id,
            "--target",
            str(format_target),
            "--json",
        )
        validated_payload = self.box.json_payload(validated)
        self.assertEqual(validated.returncode, 0, validated.stderr + validated.stdout)
        self.assertTrue(validated_payload["ok"])
        self.assertEqual(validated_payload["validation_mode"], "format_only")

        mismatch_target = self.box.vault / "工作流" / "Mismatch.md"
        mismatch_proposal = self.box.proposal(
            "mismatch", self.box._memory_text("Mismatch", "proposal version")
        )
        created, mismatch_intent = self.box.create_intent(
            actor="codex", session=session, target=mismatch_target, proposal=mismatch_proposal
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        mismatch_id = str(mismatch_intent["intent_id"])
        claimed, _ = self.box.claim(
            actor="codex", session=session, target=mismatch_target, intent_id=mismatch_id
        )
        self.assertEqual(claimed.returncode, 0, claimed.stderr + claimed.stdout)
        mismatch_target.write_text(
            self.box._memory_text("Mismatch", "different final content"), encoding="utf-8"
        )
        rejected = self.box.ctl(
            "codex",
            session,
            "intent",
            "validate",
            "--intent-id",
            mismatch_id,
            "--target",
            str(mismatch_target),
            "--json",
        )
        rejected_payload = self.box.json_payload(rejected)
        self.assertEqual(rejected.returncode, 2, rejected.stderr + rejected.stdout)
        self.assertFalse(rejected_payload["ok"])
        self.assertEqual(rejected_payload["reason_code"], "PROPOSAL_CONTENT_MISMATCH")
        mismatch_detail = rejected_payload.get("mismatch", {})
        self.assertNotIn("diff", mismatch_detail)
        self.assertIn("diff_sha256", mismatch_detail)
        self.assertNotIn("proposal version", rejected.stdout)
        self.assertNotIn("different final content", rejected.stdout)
        shown = self.box.ctl(
            "codex", session, "intent", "show", "--intent-id", mismatch_id, "--json"
        )
        shown_payload = self.box.json_payload(shown)
        self.assertEqual(shown_payload["intent"]["status"], "failed")
        self.assertEqual(shown_payload["receipt"]["reason_code"], "PROPOSAL_CONTENT_MISMATCH")
        self.assertNotIn("proposal_canonical_snapshot", json.dumps(shown_payload, ensure_ascii=False))

    def test_global_closeout_cannot_borrow_an_orphan_bound_intent(self) -> None:
        session = "codex-orphan-bound"
        target = self.box.vault / "工作流" / "Orphan.md"
        proposal = self.box.proposal("orphan", self.box._memory_text("Orphan", "bound without claim"))
        created, intent = self.box.create_intent(
            actor="codex", session=session, target=target, proposal=proposal
        )
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        intent_id = str(intent["intent_id"])

        bound = self.box.ctl(
            "codex",
            session,
            "intent",
            "bind",
            "--intent-id",
            intent_id,
            "--target",
            str(target),
            "--claim-ref",
            "orphan-direct-bind",
            "--json",
        )
        self.assertEqual(bound.returncode, 0, bound.stderr + bound.stdout)
        bound_payload = self.box.json_payload(bound)
        self.assertEqual(bound_payload["status"], "bound")
        target.write_bytes(proposal.read_bytes())
        with contextlib.closing(sqlite3.connect(self.box.state_db)) as conn, conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM memory_session_claims WHERE intent_id=?", (intent_id,)
                ).fetchone()[0],
                0,
            )

        closed, payload = self.box.closeout(
            actor="codex", session=session, global_mode=True, explicit_session=True
        )
        self.assertEqual(closed.returncode, 2, closed.stderr + closed.stdout)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["intent_error"], "PROTECTED_WRITE_WITHOUT_BOUND_INTENT")
        self.assertEqual(payload["write_intent_receipts"], [])
        self.assertEqual(
            git(self.box.git_root, "-c", "core.quotepath=false", "status", "--short"),
            "M AgentMemory/工作流/Orphan.md",
        )


if __name__ == "__main__":
    unittest.main()
