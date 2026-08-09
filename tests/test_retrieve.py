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
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_memory_index as memory_index
import agent_memory_claim as memory_claim
import agent_memory_intent as memory_intent
import agent_memory_retrieve as retrieve


def markdown(
    name: str,
    *,
    app_id: str = "yichen-content-studio",
    project_id: str = "global",
    status: str = "active",
    agent_scope: str = "shared",
    valid_until: str = "",
    extra: str = "",
) -> str:
    valid_line = f"valid_until: {valid_until}\n" if valid_until else ""
    return (
        "---\n"
        "memory_type: project\n"
        "track: project\n"
        f"app_id: {app_id}\n"
        f"project_id: {project_id}\n"
        f"status: {status}\n"
        f"agent_scope: {agent_scope}\n"
        "verified_at: 2026-08-08\n"
        f"{valid_line}"
        "---\n\n"
        f"# {name}\n\n"
        "retrievalprobe searchable body\n\n"
        "## 当前有效摘要\n\n"
        f"{name} canonical summary {extra}\n\n"
        "## 历史\n\n"
        "This must not be preferred.\n"
    )


class TempVault:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.vault = root / "vault"
        self.state_db = root / "state.sqlite"
        self.config = root / "agent-memory.toml"
        (self.vault / "项目").mkdir(parents=True)
        self.config.write_text(
            f"memory_root = {json.dumps(str(self.vault), ensure_ascii=False)}\n"
            f"git_root = {json.dumps(str(self.vault), ensure_ascii=False)}\n"
            f"state_db = {json.dumps(str(self.state_db), ensure_ascii=False)}\n",
            encoding="utf-8",
        )
        self.env = os.environ.copy()
        self.env["AGENT_MEMORY_CONFIG_FILE"] = str(self.config)
        self.env["PYTHONIOENCODING"] = "utf-8"
        self.env["PYTHONUTF8"] = "1"

    def write(self, relative_path: str, content: str | bytes) -> Path:
        target = self.vault / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
        return target

    def index(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPTS / "agent_memory_index.py"), "--init", "--scan"],
            cwd=REPO_ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stdout + completed.stderr)

    def init_git(self) -> str:
        commands = (
            ["git", "init", "-q", str(self.vault)],
            ["git", "-C", str(self.vault), "add", "."],
            [
                "git",
                "-C",
                str(self.vault),
                "-c",
                "user.name=Memory Test",
                "-c",
                "user.email=memory-test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
        )
        for command in commands:
            completed = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
            if completed.returncode != 0:
                raise AssertionError(completed.stdout + completed.stderr)
        completed = subprocess.run(
            ["git", "-C", str(self.vault), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )
        return completed.stdout.strip()

    def run_retrieve(
        self,
        *,
        wrapper: bool = True,
        project_id: str = "yichen-content-studio",
        **overrides: object,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(SCRIPTS / ("memoryctl" if wrapper else "agent_memory_retrieve.py"))]
        if wrapper:
            command.extend(["--actor", "yichen-content-studio", "retrieve"])
        else:
            command.extend(["--actor", "yichen-content-studio"])
        command.append("--json")
        request: dict[str, object] = {
            "schema_version": 1,
            "query": "retrievalprobe",
            "app_id": "yichen-content-studio",
            "max_results": 20,
        }
        if project_id:
            request["project_id"] = project_id
        request.update(overrides)
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=self.env,
            text=True,
            input=json.dumps(request, ensure_ascii=False),
            capture_output=True,
            timeout=60,
            check=False,
        )


class RetrievalIntegrationTests(unittest.TestCase):
    def test_current_markdown_frontmatter_is_authoritative_and_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            fixture.write("项目/global.md", markdown("global", project_id="global"))
            fixture.write("项目/unscoped.md", markdown("unscoped", project_id=""))
            fixture.write(
                "项目/current.md",
                markdown("current", project_id="yichen-content-studio"),
            )
            fixture.write("项目/other.md", markdown("other", project_id="other-project"))
            fixture.write("项目/app.md", markdown("app", app_id="other-app"))
            fixture.write("项目/inactive.md", markdown("inactive", status="outdated"))
            fixture.write("项目/private.md", markdown("private", agent_scope="codex"))
            expected_head = fixture.init_git()
            fixture.index()

            completed = fixture.run_retrieve()
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["git_head"], expected_head)
            by_path = {item["relative_path"]: item for item in payload["results"]}
            self.assertEqual(set(by_path), {"项目/current.md"})
            self.assertEqual(by_path["项目/current.md"]["policy"]["scope_status"], "current_project")
            self.assertEqual(by_path["项目/current.md"]["verified_at"], "2026-08-08")
            self.assertEqual(by_path["项目/current.md"]["excerpt"], "current canonical summary")
            self.assertNotIn("This must not be preferred", completed.stdout)
            creative = fixture.run_retrieve(project_id="")
            self.assertEqual(creative.returncode, 0, creative.stdout + creative.stderr)
            creative_paths = {
                item["relative_path"] for item in json.loads(creative.stdout)["results"]
            }
            self.assertEqual(creative_paths, {"项目/global.md", "项目/unscoped.md"})

    def test_stale_index_candidate_is_revalidated_and_hash_uses_current_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            stale = fixture.write("项目/stale.md", markdown("indexed", project_id="global"))
            current = fixture.write("项目/current.md", markdown("before", project_id="global"))
            fixture.init_git()
            fixture.index()

            stale.write_text(markdown("stale", project_id="global", status="outdated"), encoding="utf-8")
            current.write_text(markdown("after", project_id="global", extra="fresh"), encoding="utf-8")
            expected_hash = hashlib.sha256(current.read_bytes()).hexdigest()

            completed = fixture.run_retrieve(project_id="")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            by_path = {item["relative_path"]: item for item in payload["results"]}
            self.assertNotIn("项目/stale.md", by_path)
            self.assertEqual(by_path["项目/current.md"]["sha256"], expected_hash)
            self.assertEqual(by_path["项目/current.md"]["excerpt"], "after canonical summary fresh")
            self.assertTrue(
                any(
                    warning.get("relative_path") == "项目/stale.md"
                    and warning.get("reason") == "STATUS_NOT_ACTIVE"
                    for warning in payload["warnings"]
                )
            )

    def test_hash_query_git_order_and_read_only_state_are_stable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            first = fixture.write("项目/a.md", markdown("alpha", project_id="global"))
            second = fixture.write("项目/b.md", markdown("beta", project_id="global"))
            expected_head = fixture.init_git()
            fixture.index()
            vault_before = {
                path.relative_to(fixture.vault).as_posix(): (
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    path.stat().st_mtime_ns,
                )
                for path in (first, second)
            }
            db_before = fixture.state_db.read_bytes()
            with contextlib.closing(sqlite3.connect(fixture.state_db)) as conn:
                counts_before = {
                    table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("memory_docs", "memory_fts", "memory_search_log", "meta")
                }

            first_run = fixture.run_retrieve(project_id="")
            second_run = fixture.run_retrieve(project_id="")
            self.assertEqual(first_run.returncode, 0, first_run.stdout + first_run.stderr)
            self.assertEqual(second_run.returncode, 0, second_run.stdout + second_run.stderr)
            first_payload = json.loads(first_run.stdout)
            second_payload = json.loads(second_run.stdout)
            self.assertEqual(first_payload["query_hash"], retrieve.query_sha256("retrievalprobe"))
            self.assertEqual(first_payload["query_hash"], second_payload["query_hash"])
            self.assertEqual(first_payload["git_head"], expected_head)
            self.assertEqual(
                [(item["relative_path"], item["sha256"]) for item in first_payload["results"]],
                [(item["relative_path"], item["sha256"]) for item in second_payload["results"]],
            )
            self.assertEqual(fixture.state_db.read_bytes(), db_before)
            with contextlib.closing(sqlite3.connect(fixture.state_db)) as conn:
                counts_after = {
                    table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("memory_docs", "memory_fts", "memory_search_log", "meta")
                }
            self.assertEqual(counts_after, counts_before)
            vault_after = {
                path.relative_to(fixture.vault).as_posix(): (
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    path.stat().st_mtime_ns,
                )
                for path in (first, second)
            }
            self.assertEqual(vault_after, vault_before)
            status = subprocess.run(
                ["git", "-C", str(fixture.vault), "status", "--porcelain"],
                text=True,
                capture_output=True,
                timeout=30,
                check=True,
            )
            self.assertEqual(status.stdout, "")

    def test_invalid_utf8_oversize_and_secret_are_warnings_without_leaks(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            fixture.write(
                "项目/bad.md",
                b"---\nmemory_type: project\ntrack: project\n"
                b"app_id: yichen-content-studio\nproject_id: global\n"
                b"agent_scope: shared\nstatus: active\n---\nretrievalprobe\xff\n",
            )
            fixture.write("项目/big.md", markdown("big", extra="x" * 5000))
            # Keep the public fixture source free of a credential-shaped
            # literal while still exercising the runtime detector.
            secret = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
            fixture.write("项目/secret.md", markdown("secret", extra=secret))
            fixture.init_git()
            fixture.index()

            completed = fixture.run_retrieve(project_id="", max_file_bytes=1024)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["results"], [])
            reasons = {item.get("reason") for item in payload["warnings"]}
            self.assertTrue({"CONTENT_NOT_UTF8", "FILE_TOO_LARGE", "SECRET_MATERIAL"} <= reasons)
            self.assertNotIn(secret, completed.stdout)

    def test_live_verification_policy_comes_from_current_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            fixture.write(
                "项目/expired.md",
                markdown("expired", project_id="global", valid_until="2020-01-01"),
            )
            fixture.init_git()
            fixture.index()
            completed = fixture.run_retrieve(project_id="")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            item = json.loads(completed.stdout)["results"][0]
            self.assertEqual(item["policy"]["time_status"], "expired")
            self.assertTrue(item["live_verification"]["required"])
            self.assertIn("expired_memory_reference_only", item["live_verification"]["reasons"])

    def test_missing_index_degrades_without_creating_state(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            fixture.write("项目/global.md", markdown("global", project_id="global"))
            fixture.init_git()
            self.assertFalse(fixture.state_db.exists())
            completed = fixture.run_retrieve(project_id="")
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["results"], [])
            self.assertFalse(fixture.state_db.exists())
            codes = {warning["code"] for warning in payload["warnings"]}
            self.assertIn("SEARCH_INDEX_MISSING", codes)
            self.assertIn("SEARCH_BACKENDS_UNAVAILABLE", codes)


class RetrievalBoundaryUnitTests(unittest.TestCase):
    def test_content_studio_scope_request_requires_fixed_app_and_safe_project(self) -> None:
        for app_id, project_id, reason in (
            ("", "", "APP_ID_REQUIRED"),
            ("other-app", "", "APP_ID_UNSUPPORTED"),
            ("yichen-content-studio", "global", "PROJECT_ID_INVALID"),
            ("yichen-content-studio", "one,two", "PROJECT_ID_INVALID"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaises(retrieve.RetrievalProtocolError) as raised:
                    retrieve.validate_studio_scope_request(app_id, project_id)
                self.assertEqual(raised.exception.code, reason)

    def test_content_studio_cli_rejects_private_query_in_argv(self) -> None:
        private_query = "private-query-must-not-reach-child-94731"
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "memoryctl"),
                "--actor",
                "yichen-content-studio",
                "retrieve",
                private_query,
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn(private_query, completed.stdout + completed.stderr)

    def test_content_studio_actor_is_accepted_without_inheriting_codex_session(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            [
                "agent_memory_claim.py",
                "--actor",
                "yichen-content-studio",
                "--session-id",
                "plugin-session",
                "list",
            ],
        ):
            self.assertEqual(memory_claim.parse_args().actor, "yichen-content-studio")
        with mock.patch.object(
            sys,
            "argv",
            [
                "agent_memory_intent.py",
                "--actor",
                "yichen-content-studio",
                "--session-id",
                "plugin-session",
                "show",
                "--intent-id",
                "example",
            ],
        ):
            self.assertEqual(memory_intent.parse_args().actor, "yichen-content-studio")
        with mock.patch.dict(
            os.environ,
            {"CODEX_THREAD_ID": "outer-codex-session"},
            clear=False,
        ):
            os.environ.pop("AGENT_MEMORY_SESSION_ID", None)
            self.assertEqual(memory_intent._session_value("", "yichen-content-studio"), "")

    def run_direct(self, vault: Path, candidates: list[retrieve.Candidate], **overrides: object) -> dict[str, object]:
        resolved_vault = vault.resolve()
        defaults: dict[str, object] = {
            "actor": "yichen-content-studio",
            "app_id": "yichen-content-studio",
            "project_id": "yichen-content-studio",
            "query": "retrievalprobe",
            "max_results": 20,
            "max_file_bytes": 4096,
            "max_total_bytes": 16384,
            "max_excerpt_bytes": 1024,
            "candidates": candidates,
        }
        defaults.update(overrides)
        with (
            mock.patch.object(retrieve, "VAULT_ROOT", vault),
            mock.patch.object(retrieve, "GIT_ROOT", vault),
            mock.patch.object(memory_intent, "VAULT_ROOT", vault),
            mock.patch.object(memory_index, "VAULT_ROOT", resolved_vault),
        ):
            return retrieve.retrieve(**defaults)  # type: ignore[arg-type]

    def test_escape_symlink_non_markdown_and_non_formal_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            vault = root / "vault"
            (vault / "项目").mkdir(parents=True)
            outside = root / "outside.md"
            outside.write_text(markdown("outside"), encoding="utf-8")
            link = vault / "项目" / "link.md"
            link.symlink_to(outside)
            text_file = vault / "项目" / "not-markdown.txt"
            text_file.write_text("retrievalprobe", encoding="utf-8")
            private_log = vault / "logs" / "private.md"
            private_log.parent.mkdir()
            private_log.write_text(markdown("log"), encoding="utf-8")
            candidates = [
                retrieve.Candidate(str(outside), "", 1),
                retrieve.Candidate(str(link), "项目/link.md", 2),
                retrieve.Candidate(str(text_file), "项目/not-markdown.txt", 3),
                retrieve.Candidate(str(private_log), "logs/private.md", 4),
            ]
            payload = self.run_direct(vault, candidates)
            self.assertEqual(payload["results"], [])
            reasons = {item.get("reason") for item in payload["warnings"]}  # type: ignore[index]
            self.assertTrue(
                {"PATH_OUTSIDE_BOUNDARY", "SYMLINK_FORBIDDEN", "TARGET_NOT_MARKDOWN", "NON_FORMAL_PATH"}
                <= reasons
            )
            serialized = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn(str(outside), serialized)

    def test_malformed_frontmatter_and_total_budget_are_structured_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            malformed = project / "malformed.md"
            malformed.write_text("---\nstatus: active\nretrievalprobe\n", encoding="utf-8")
            one = project / "one.md"
            two = project / "two.md"
            one.write_text(markdown("one", project_id="global", extra="x" * 80), encoding="utf-8")
            two.write_text(markdown("two", project_id="global", extra="y" * 80), encoding="utf-8")
            # Invalid files still consume the source-inspection budget; this
            # prevents a run from reading unbounded rejected content.
            budget = len(malformed.read_bytes()) + len(one.read_bytes()) + 1
            candidates = [
                retrieve.Candidate(str(malformed), "项目/malformed.md", 1),
                retrieve.Candidate(str(one), "项目/one.md", 2),
                retrieve.Candidate(str(two), "项目/two.md", 3),
            ]
            payload = self.run_direct(vault, candidates, project_id="", max_total_bytes=budget)
            self.assertEqual(
                [item["relative_path"] for item in payload["results"]],  # type: ignore[index]
                ["项目/one.md"],
            )
            reasons = {item.get("reason") for item in payload["warnings"]}  # type: ignore[index]
            self.assertIn("FRONTMATTER_INVALID", reasons)
            self.assertIn("TOTAL_BYTE_BUDGET", reasons)

    def test_duplicate_security_frontmatter_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            duplicate = project / "duplicate.md"
            duplicate.write_text(
                markdown("duplicate", project_id="global").replace(
                    "status: active\n",
                    "status: outdated\nstatus: active\n",
                ),
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [retrieve.Candidate(str(duplicate), "项目/duplicate.md", 1)],
            )
            self.assertEqual(payload["results"], [])
            self.assertTrue(
                any(
                    warning.get("reason") == "FRONTMATTER_DUPLICATE_KEY"
                    for warning in payload["warnings"]  # type: ignore[index]
                )
            )

    def test_no_project_defaults_to_global_and_excerpt_truncation_is_utf8_safe(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            global_file = project / "global.md"
            current_file = project / "current.md"
            global_file.write_text(
                markdown("global", project_id="global", extra="中文" * 100),
                encoding="utf-8",
            )
            current_file.write_text(
                markdown("current", project_id="yichen-content-studio"),
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [
                    retrieve.Candidate(str(global_file), "项目/global.md", 1),
                    retrieve.Candidate(str(current_file), "项目/current.md", 2),
                ],
                project_id="",
                max_excerpt_bytes=31,
            )
            self.assertEqual(
                [item["relative_path"] for item in payload["results"]],  # type: ignore[index]
                ["项目/global.md"],
            )
            item = payload["results"][0]  # type: ignore[index]
            self.assertTrue(item["excerpt_truncated"])
            self.assertLessEqual(len(item["excerpt"].encode("utf-8")), 31)
            self.assertNotIn("query", payload)
            self.assertTrue(
                any(
                    warning.get("reason") == "PROJECT_SCOPE_MISMATCH"
                    for warning in payload["warnings"]  # type: ignore[index]
                )
            )

    def test_query_hash_normalizes_width_and_whitespace(self) -> None:
        self.assertEqual(retrieve.query_sha256("Ｆoo   bar"), retrieve.query_sha256("Foo bar"))
        self.assertNotEqual(retrieve.query_sha256("Foo bar"), retrieve.query_sha256("Foo baz"))

    def test_missing_root_is_protocol_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            missing = Path(raw_root) / "missing"
            with mock.patch.object(retrieve, "VAULT_ROOT", missing):
                with self.assertRaisesRegex(retrieve.RetrievalProtocolError, "VAULT_MISSING"):
                    retrieve.validate_vault_root()


if __name__ == "__main__":
    unittest.main()
