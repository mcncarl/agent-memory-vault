from __future__ import annotations

import contextlib
import datetime as dt
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
import agent_memory_search as search
from tests.state_fixture import initialize_full_state


def markdown(
    name: str,
    *,
    app_id: str = "ailu",
    project_id: str = "global",
    status: str = "active",
    agent_scope: str = "shared",
    valid_until: str = "",
    verified_at: str = "2026-08-08",
    review_after_days: int | None = None,
    verification_mode: str = "",
    memory_id: str = "",
    extra: str = "",
) -> str:
    valid_line = f"valid_until: {valid_until}\n" if valid_until else ""
    verified_line = f"verified_at: {verified_at}\n" if verified_at else ""
    review_line = f"review_after_days: {review_after_days}\n" if review_after_days else ""
    verification_line = f"verification_mode: {verification_mode}\n" if verification_mode else ""
    memory_id_line = f"memory_id: {memory_id}\n" if memory_id else ""
    return (
        "---\n"
        "memory_type: project\n"
        "track: project\n"
        f"app_id: {app_id}\n"
        f"project_id: {project_id}\n"
        f"status: {status}\n"
        f"agent_scope: {agent_scope}\n"
        f"{memory_id_line}"
        f"{verified_line}"
        f"{valid_line}"
        f"{review_line}"
        f"{verification_line}"
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
        root = root.resolve()
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
        initialize_full_state(self.state_db)
        self.env = os.environ.copy()
        self.env["AGENT_MEMORY_CONFIG_FILE"] = str(self.config)
        self.env["AGENT_MEMORY_ROOT"] = str(self.vault)
        self.env["AGENT_MEMORY_GIT_ROOT"] = str(self.vault)
        self.env["AGENT_MEMORY_STATE_DB"] = str(self.state_db)
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
        project_id: str = "ailu",
        **overrides: object,
    ) -> subprocess.CompletedProcess[str]:
        command = (
            [str(SCRIPTS / "memoryctl")]
            if wrapper
            else [sys.executable, str(SCRIPTS / "agent_memory_retrieve.py")]
        )
        if wrapper:
            command.extend(["--actor", "ailu", "retrieve"])
        else:
            command.extend(["--actor", "ailu"])
        command.append("--json")
        request: dict[str, object] = {
            "schema_version": 2,
            "query": "retrievalprobe",
            "app_id": "ailu",
            "semantic_mode": "off",
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

    def run_file_view(
        self,
        view: str,
        relative_path: str,
        *,
        project_id: str = "outline-project",
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            str(SCRIPTS / "memoryctl"),
            "--actor",
            "codex",
            "retrieve",
            "--view",
            view,
            "--file",
            relative_path,
            "--project-id",
            project_id,
            "--json",
        ]
        option_names = {
            "section_id": "--section-id",
            "expected_sha256": "--expected-sha256",
            "max_excerpt_bytes": "--max-excerpt-bytes",
            "offset_chars": "--offset-chars",
            "outline_offset": "--outline-offset",
        }
        if bool(options.pop("observe", False)):
            command.append("--observe")
        for key, value in options.items():
            command.extend([option_names[key], str(value)])
        return subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )


class RetrievalIntegrationTests(unittest.TestCase):
    def test_confirmed_closeout_alias_is_top_five_in_search_and_canonical_retrieve(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            template_path = (
                REPO_ROOT
                / "templates"
                / "vault"
                / "工作流"
                / "Agent记忆收尾决策规则.md"
            )
            alias_text = (
                template_path.read_text(encoding="utf-8")
                .replace("{{APP_ID}}", "ailu")
                .replace("{{USER_ID}}", "test-user")
                .replace("{{AGENT_ID}}", "shared")
            )
            self.assertIn("risk_class: ordinary\n", alias_text)
            self.assertNotIn("verified_at:", alias_text)
            for alias in ("对话结束", "自动归档", "记忆收尾", "对话结束归档"):
                self.assertIn(f"  - {alias}", alias_text)
            self.assertIn(
                "- 真实用户表达别名：对话结束、自动归档、记忆收尾、对话结束归档、"
                "Codex 每次对话结束怎么自动归档。",
                alias_text,
            )
            expected_path = "工作流/Agent记忆收尾决策规则.md"
            fixture.write(expected_path, alias_text)
            for index in range(8):
                fixture.write(
                    f"项目/distractor-{index}.md",
                    markdown(f"Codex workflow {index}", project_id="ailu", extra="普通工作流参考"),
                )
            fixture.init_git()
            fixture.index()
            query = "Codex 每次对话结束怎么自动归档"

            searched = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "agent_memory_search.py"),
                    "--query-stdin",
                    "--current-project",
                    "agent-memory-vault-closeout",
                    "--semantic-mode",
                    "off",
                    "--no-log",
                    "--limit",
                    "5",
                    "--json",
                ],
                cwd=REPO_ROOT,
                env=fixture.env,
                input=query,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(searched.returncode, 0, searched.stdout + searched.stderr)
            self.assertIn(
                expected_path,
                [row["rel_path"] for row in json.loads(searched.stdout)["results"][:5]],
            )

            retrieved = fixture.run_retrieve(
                query=query,
                project_id="agent-memory-vault-closeout",
                max_results=5,
            )
            self.assertEqual(retrieved.returncode, 0, retrieved.stdout + retrieved.stderr)
            self.assertIn(
                expected_path,
                [row["relative_path"] for row in json.loads(retrieved.stdout)["results"][:5]],
            )

    def test_source_opened_is_automatic_version_bound_and_uses_opaque_task_ref(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            stable_memory_id = "a" * 64
            fixture.write(
                "项目/observed.md",
                markdown(
                    "Observed",
                    project_id="outline-project",
                    memory_id=stable_memory_id,
                ),
            )
            fixture.init_git()
            fixture.index()
            raw_task = "private-retrieve-task-8821"
            fixture.env["AGENT_MEMORY_OBSERVABILITY_ENABLED"] = "true"
            # Earlier in-process memoryctl tests may leave their ephemeral
            # maintenance nonce in the parent environment.  A real wrapper
            # process exits after use, so this integration fixture must bind
            # the read to the explicit Codex task instead.
            fixture.env.pop("AGENT_MEMORY_TASK_ID", None)
            fixture.env["CODEX_THREAD_ID"] = raw_task
            completed = fixture.run_file_view(
                "outline",
                "项目/observed.md",
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["observation"]["recorded"], 1)
            with contextlib.closing(sqlite3.connect(fixture.state_db)) as conn:
                task_id, source, read_mode, memory_ids_json, memory_versions_json = conn.execute(
                    "SELECT task_id,source,read_mode,memory_ids_json,memory_versions_json "
                    "FROM memory_use_events "
                    "WHERE event_type='source_opened'"
                ).fetchone()
            self.assertEqual(len(task_id), 64)
            self.assertEqual(source, "tool_observed")
            self.assertEqual(read_mode, "outline")
            self.assertEqual(json.loads(memory_ids_json), [stable_memory_id])
            source_version = json.loads(memory_versions_json)[0]
            self.assertEqual(source_version["memory_id"], stable_memory_id)
            with (
                mock.patch.object(retrieve.observability, "STATE_DB", fixture.state_db),
                mock.patch.object(retrieve.observability, "assert_runtime_ready", return_value={"ready": True}),
                mock.patch.dict(
                    os.environ,
                    {
                        "AGENT_MEMORY_OBSERVABILITY_ENABLED": "true",
                        "AGENT_MEMORY_TASK_ID": "",
                        "CODEX_THREAD_ID": raw_task,
                    },
                ),
            ):
                retrieve.observability.record_declared_event(
                    actor="codex",
                    task_id=retrieve.observability.task_ref(raw_task, "codex"),
                    event_type="adoption_declared",
                    source="agent_declared",
                    value="adopted",
                    memory_ids=[stable_memory_id],
                    memory_versions=[source_version],
                    reason_code="workflow_rule",
                    confidence="high",
                )
            with contextlib.closing(sqlite3.connect(fixture.state_db)) as conn:
                adoption_ids, adoption_versions = conn.execute(
                    "SELECT memory_ids_json,memory_versions_json FROM memory_use_events "
                    "WHERE event_type='adoption_declared'"
                ).fetchone()
            self.assertEqual(json.loads(adoption_ids), [stable_memory_id])
            self.assertEqual(json.loads(adoption_versions)[0]["memory_id"], stable_memory_id)
            self.assertNotIn(raw_task.encode(), fixture.state_db.read_bytes())

    def test_outline_and_section_views_use_current_source_and_are_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            source_text = (
                "---\n"
                "memory_type: project\n"
                "track: project\n"
                "app_id: ailu\n"
                "project_id: outline-project\n"
                "status: active\n"
                "agent_scope: shared\n"
                "verified_at: 2026-08-08\n"
                "# frontmatter comment is not a heading\n"
                "---\n\n"
                "# Root\n\n"
                "```markdown\n"
                "## fenced fake heading\n"
                "```\n\n"
                "## Parent\n"
                "父章节第一行。\n"
                "### Repeated\n"
                "子章节内容甲乙丙丁戊己庚辛壬癸。\n"
                "#### Deep\n"
                "deep body\n"
                "##### Five\n"
                "###### Six\n"
                "deepest body\n"
                "### Repeated\n"
                "second child\n"
                "## Sibling\n"
                "must not be in parent\n"
            )
            source = fixture.write("项目/outline.md", source_text)
            fixture.init_git()
            before = (source.read_bytes(), source.stat().st_mtime_ns)
            state_before = fixture.state_db.read_bytes()

            outlined = fixture.run_file_view("outline", "项目/outline.md")
            self.assertEqual(outlined.returncode, 0, outlined.stdout + outlined.stderr)
            payload = json.loads(outlined.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["view"], "outline")
            item = payload["results"][0]
            expected_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(item["source_sha256"], expected_hash)
            outline = item["outline"]
            self.assertEqual(
                [(row["section_id"], row["level"], row["title"]) for row in outline],
                [
                    ("s0001", 1, "Root"),
                    ("s0002", 2, "Parent"),
                    ("s0003", 3, "Repeated"),
                    ("s0004", 4, "Deep"),
                    ("s0005", 5, "Five"),
                    ("s0006", 6, "Six"),
                    ("s0007", 3, "Repeated"),
                    ("s0008", 2, "Sibling"),
                ],
            )
            self.assertEqual(outline[1]["parent_section_id"], "s0001")
            self.assertEqual(outline[3]["parent_section_id"], "s0003")
            self.assertEqual(outline[5]["parent_section_id"], "s0005")
            self.assertEqual(
                outline[1]["size_bytes"],
                outline[1]["end_byte"] - outline[1]["start_byte"],
            )
            self.assertFalse(item["truncated"])
            self.assertIsNone(item["next_outline_offset"])

            pages: list[str] = []
            offset = 0
            while True:
                sectioned = fixture.run_file_view(
                    "section",
                    "项目/outline.md",
                    section_id="s0002",
                    expected_sha256=expected_hash,
                    max_excerpt_bytes=23,
                    offset_chars=offset,
                )
                self.assertEqual(sectioned.returncode, 0, sectioned.stdout + sectioned.stderr)
                section_payload = json.loads(sectioned.stdout)["results"][0]
                pages.append(section_payload["excerpt"])
                self.assertLessEqual(section_payload["returned_bytes"], 23)
                next_offset = section_payload["next_offset_chars"]
                if next_offset is None:
                    break
                self.assertGreater(next_offset, offset)
                offset = next_offset
            reconstructed = "".join(pages)
            self.assertTrue(reconstructed.startswith("## Parent\n"))
            self.assertIn("#### Deep\ndeep body", reconstructed)
            self.assertIn("### Repeated\nsecond child", reconstructed)
            self.assertNotIn("## Sibling", reconstructed)
            self.assertEqual((source.read_bytes(), source.stat().st_mtime_ns), before)
            self.assertEqual(fixture.state_db.read_bytes(), state_before)
            status = subprocess.run(
                ["git", "-C", str(fixture.vault), "status", "--porcelain"],
                text=True,
                capture_output=True,
                timeout=30,
                check=True,
            )
            self.assertEqual(status.stdout, "")

            source.write_text(
                source_text.replace("status: active", "status: outdated")
                + "\nchanged after outline\n",
                encoding="utf-8",
            )
            stale = fixture.run_file_view(
                "section",
                "项目/outline.md",
                section_id="s0002",
                expected_sha256=expected_hash,
            )
            self.assertEqual(stale.returncode, 2)
            self.assertEqual(json.loads(stale.stdout)["error"]["code"], "STALE_OUTLINE")

    def test_outline_pages_are_utf8_safe_and_bounded_by_excerpt_budget(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            body = "\n".join(f"## 第{i:02d}节 标题\n正文{i}" for i in range(40))
            fixture.write(
                "项目/dense-outline.md",
                (
                    "---\n"
                    "memory_type: project\n"
                    "track: project\n"
                    "app_id: ailu\n"
                    "project_id: outline-project\n"
                    "status: active\n"
                    "agent_scope: shared\n"
                    "verified_at: 2026-08-08\n"
                    "---\n\n"
                    f"{body}\n"
                ),
            )
            fixture.init_git()

            offset = 0
            section_ids: list[str] = []
            while True:
                completed = fixture.run_file_view(
                    "outline",
                    "项目/dense-outline.md",
                    max_excerpt_bytes=900,
                    outline_offset=offset,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                item = json.loads(completed.stdout)["results"][0]
                encoded_outline = json.dumps(
                    item["outline"], ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
                self.assertEqual(item["outline_returned_bytes"], len(encoded_outline))
                self.assertLessEqual(len(encoded_outline), 900)
                self.assertEqual(item["outline_offset"], offset)
                self.assertEqual(item["document"]["heading_count"], 40)
                section_ids.extend(row["section_id"] for row in item["outline"])
                next_offset = item["next_outline_offset"]
                if next_offset is None:
                    self.assertFalse(item["truncated"])
                    break
                self.assertTrue(item["truncated"])
                self.assertGreater(next_offset, offset)
                offset = next_offset
            self.assertEqual(section_ids, [f"s{i:04d}" for i in range(1, 41)])

    def test_current_markdown_frontmatter_is_authoritative_and_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            fixture.write("项目/global.md", markdown("global", project_id="global"))
            fixture.write("项目/unscoped.md", markdown("unscoped", project_id=""))
            fixture.write(
                "项目/current.md",
                markdown("current", project_id="ailu"),
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
            self.assertTrue(by_path["项目/current.md"]["can_authorize_action"])
            self.assertEqual(by_path["项目/current.md"]["verified_at"], "2026-08-08")
            self.assertEqual(by_path["项目/current.md"]["excerpt"], "current canonical summary")
            self.assertNotIn("This must not be preferred", completed.stdout)
            missing_scope = fixture.run_retrieve(project_id="")
            self.assertEqual(missing_scope.returncode, 2)
            self.assertEqual(json.loads(missing_scope.stdout)["error"]["code"], "PROJECT_ID_REQUIRED")

    def test_stale_index_candidate_is_revalidated_and_hash_uses_current_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            stale = fixture.write("项目/stale.md", markdown("indexed", project_id="ailu"))
            current = fixture.write("项目/current.md", markdown("before", project_id="ailu"))
            fixture.init_git()
            fixture.index()

            stale.write_text(markdown("stale", project_id="ailu", status="outdated"), encoding="utf-8")
            current.write_text(markdown("after", project_id="ailu", extra="fresh"), encoding="utf-8")
            expected_hash = hashlib.sha256(current.read_bytes()).hexdigest()

            completed = fixture.run_retrieve()
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

    def test_hash_query_git_order_and_privacy_safe_search_telemetry_are_stable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            first = fixture.write("项目/a.md", markdown("alpha", project_id="ailu"))
            second = fixture.write("项目/b.md", markdown("beta", project_id="ailu"))
            expected_head = fixture.init_git()
            fixture.index()
            vault_before = {
                path.relative_to(fixture.vault).as_posix(): (
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    path.stat().st_mtime_ns,
                )
                for path in (first, second)
            }
            with contextlib.closing(sqlite3.connect(fixture.state_db)) as conn:
                counts_before = {
                    table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("memory_docs", "memory_fts", "memory_search_log", "meta")
                }

            first_run = fixture.run_retrieve()
            second_run = fixture.run_retrieve()
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
            with contextlib.closing(sqlite3.connect(fixture.state_db)) as conn:
                counts_after = {
                    table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("memory_docs", "memory_fts", "memory_search_log", "meta")
                }
                search_rows = conn.execute(
                    "SELECT query,query_sha256,sources FROM memory_search_log ORDER BY id"
                ).fetchall()
            self.assertEqual(counts_after["memory_docs"], counts_before["memory_docs"])
            self.assertEqual(counts_after["memory_fts"], counts_before["memory_fts"])
            self.assertEqual(counts_after["meta"], counts_before["meta"])
            self.assertEqual(
                counts_after["memory_search_log"],
                counts_before["memory_search_log"] + 2,
            )
            self.assertEqual([row[0] for row in search_rows[-2:]], ["", ""])
            self.assertEqual(
                [row[1] for row in search_rows[-2:]],
                [retrieve.query_sha256("retrievalprobe")] * 2,
            )
            self.assertEqual(
                [row[2] for row in search_rows[-2:]],
                ["canonical_retrieve", "canonical_retrieve"],
            )
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
                b"app_id: ailu\nproject_id: global\n"
                b"agent_scope: shared\nstatus: active\n---\nretrievalprobe\xff\n",
            )
            fixture.write("项目/big.md", markdown("big", extra="x" * 5000))
            # Keep the public fixture source free of a credential-shaped
            # literal while still exercising the runtime detector.
            secret = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
            fixture.write("项目/secret.md", markdown("secret", extra=secret))
            fixture.init_git()
            fixture.index()

            completed = fixture.run_retrieve(project_id="global", max_file_bytes=1024)
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
                markdown("expired", project_id="ailu", valid_until="2020-01-01"),
            )
            fixture.init_git()
            fixture.index()
            completed = fixture.run_retrieve()
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            item = json.loads(completed.stdout)["results"][0]
            self.assertEqual(item["policy"]["time_status"], "expired")
            self.assertTrue(item["live_verification"]["required"])
            self.assertIn("expired_memory_reference_only", item["live_verification"]["reasons"])

    def test_incomplete_state_fails_closed_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            fixture = TempVault(Path(raw_root))
            fixture.write("项目/global.md", markdown("global", project_id="global"))
            fixture.init_git()
            incomplete_state = fixture.root / "incomplete-state.sqlite"
            with sqlite3.connect(incomplete_state) as connection:
                memory_intent.ensure_schema(connection)
            fixture.env["AGENT_MEMORY_STATE_DB"] = str(incomplete_state)
            before = fixture.state_db.read_bytes()
            incomplete_before = incomplete_state.read_bytes()
            completed = fixture.run_retrieve(project_id="global")
            self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["reason_code"], "RUNTIME_TRANSITION_INCOMPLETE")
            self.assertEqual(fixture.state_db.read_bytes(), before)
            self.assertEqual(incomplete_state.read_bytes(), incomplete_before)


class RetrievalBoundaryUnitTests(unittest.TestCase):
    def test_canonical_retrieve_dedupes_current_explicit_memory_id(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            memory_id = "a" * 64
            first = project / "first.md"
            second = project / "second.md"
            first.write_text(
                markdown("first", project_id="ailu", memory_id=memory_id),
                encoding="utf-8",
            )
            second.write_text(
                markdown("second", project_id="ailu", memory_id=memory_id),
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [
                    retrieve.Candidate(str(first), "项目/first.md", 1, memory_id),
                    retrieve.Candidate(str(second), "项目/second.md", 2, memory_id),
                ],
            )
        self.assertEqual(payload["result_count"], 1)
        self.assertEqual(payload["results"][0]["memory_id"], memory_id)  # type: ignore[index]
        self.assertIn(
            "DUPLICATE_MEMORY_ID",
            {item.get("reason") for item in payload["warnings"]},  # type: ignore[index]
        )

    def test_candidate_memory_id_must_match_current_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "current.md"
            target.write_text(
                markdown("current", project_id="ailu", memory_id="a" * 64),
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [retrieve.Candidate(str(target), "项目/current.md", 1, "b" * 64)],
            )
        self.assertEqual(payload["results"], [])
        self.assertIn(
            "MEMORY_ID_INDEX_STALE",
            {item.get("reason") for item in payload["warnings"]},  # type: ignore[index]
        )

    def test_canonical_metadata_gate_shadows_then_enforces_without_changing_live_reasons(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "incomplete.md"
            target.write_text(
                markdown(
                    "incomplete",
                    project_id="global",
                    verification_mode="structural",
                ),
                encoding="utf-8",
            )
            candidate = retrieve.Candidate(str(target), "项目/incomplete.md", 1)
            shadow_projection = {
                "configured_mode": "shadow",
                "effective_mode": "shadow",
                "would_block_count": 1,
                "reason_codes": sorted(retrieve.shadow_gate.METADATA_GATE_REASON_CODES),
                "reason_fingerprint": "a" * 64,
                "enforced": False,
            }
            with mock.patch.object(
                retrieve.shadow_gate,
                "metadata_gate_projection",
                return_value=shadow_projection,
            ):
                shadow_payload = self.run_direct(
                    vault,
                    [candidate],
                    actor="test",
                    app_id="",
                    project_id="",
                )
            shadow_item = shadow_payload["results"][0]  # type: ignore[index]
            self.assertTrue(shadow_item["can_authorize_action"])
            self.assertTrue(shadow_item["metadata_gate_would_block"])
            self.assertIn(
                "metadata_gate_would_block",
                shadow_item["policy"]["warnings"],
            )
            self.assertFalse(shadow_item["requires_live_verification"])
            self.assertNotIn(
                "metadata_gate_would_block",
                shadow_item["live_verification"]["reasons"],
            )

            enforce_projection = {
                **shadow_projection,
                "configured_mode": "enforce",
                "effective_mode": "enforce",
                "enforced": True,
            }
            with mock.patch.object(
                retrieve.shadow_gate,
                "metadata_gate_projection",
                return_value=enforce_projection,
            ):
                enforce_payload = self.run_direct(
                    vault,
                    [candidate],
                    actor="test",
                    app_id="",
                    project_id="",
                )
            enforce_item = enforce_payload["results"][0]  # type: ignore[index]
            self.assertFalse(enforce_item["can_authorize_action"])
            self.assertFalse(enforce_item["policy"]["can_authorize_action"])

    def test_canonical_action_sensitive_enforce_requires_current_exact_fact_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            vault = root / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            today = dt.date.today().isoformat()
            target = project / "事实-owner.md"
            target.write_text(
                "---\n"
                f"memory_id: {'a' * 64}\n"
                "memory_type: fact\ntrack: project\n"
                "app_id: agent-memory\nproject_id: global\nagent_scope: shared\n"
                "status: active\nrisk_class: action_sensitive\n"
                "temporal_policy: reviewable\nreview_after_days: 90\n"
                "fact_key: project.owner\n"
                f"valid_from: {today}\nverified_at: {today}\n"
                "---\n# Owner\n\nretrievalprobe\n",
                encoding="utf-8",
            )
            raw_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
            state_db = root / "state.sqlite"
            with contextlib.closing(sqlite3.connect(state_db)) as conn:
                conn.execute(
                    """
                    CREATE TABLE memory_write_receipts(
                      writer_protocol_version INTEGER,
                      target_rel_path TEXT,
                      outcome TEXT,
                      final_raw_sha256 TEXT,
                      git_commit TEXT,
                      source_class TEXT,
                      knowledge_kind TEXT,
                      asserted_by_sha256 TEXT,
                      safety_decision TEXT,
                      evidence_ref_sha256 TEXT,
                      created_at TEXT
                    )
                    """
                )
                # A durable receipt for another content version must not pass.
                conn.execute(
                    "INSERT INTO memory_write_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        2,
                        "项目/事实-owner.md",
                        "completed",
                        "b" * 64,
                        "c" * 40,
                        "user_direct",
                        "fact",
                        "d" * 64,
                        "ALLOW",
                        "e" * 64,
                        "2026-08-25T00:00:00+00:00",
                    ),
                )
                conn.commit()
            state_db.chmod(0o600)

            temporal_current = {
                "fact_key": "project.owner",
                "valid_from": today,
                "fact_status": "current",
                "current_fact_path": "项目/事实-owner.md",
                "superseded_by": "",
                "superseded_at": "",
                "fact_reason_code": "",
            }
            real_projection = retrieve.shadow_gate.metadata_gate_projection

            def enforce_projection(reason_sets: object) -> dict[str, object]:
                return real_projection(
                    reason_sets,  # type: ignore[arg-type]
                    config={"observability": {"metadata_enforcement": "enforce"}},
                    cutover_verified=True,
                )

            with (
                mock.patch.object(retrieve.shadow_gate, "STATE_DB", state_db),
                mock.patch.object(
                    retrieve,
                    "_canonical_temporal_policy",
                    return_value=temporal_current,
                ),
                mock.patch.object(
                    retrieve.shadow_gate,
                    "metadata_gate_projection",
                    side_effect=enforce_projection,
                ),
            ):
                before = state_db.read_bytes()
                missing_payload = self.run_direct(
                    vault,
                    [retrieve.Candidate(str(target), "项目/事实-owner.md", 1)],
                    actor="test",
                    app_id="",
                    project_id="",
                    _observation_capability=retrieve._SYNTHETIC_BENCHMARK_CAPABILITY,
                )
                missing_item = missing_payload["results"][0]  # type: ignore[index]
                self.assertEqual(
                    missing_item["metadata_gate_reason_codes"],
                    ["METADATA_CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING"],
                )
                self.assertFalse(missing_item["can_authorize_action"])
                self.assertEqual(state_db.read_bytes(), before)

                with contextlib.closing(sqlite3.connect(state_db)) as conn:
                    conn.execute(
                        "INSERT INTO memory_write_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            2,
                            "项目/事实-owner.md",
                            "completed",
                            raw_sha256,
                            "f" * 40,
                            "user_direct",
                            "fact",
                            "1" * 64,
                            "ALLOW",
                            "2" * 64,
                            "2026-08-25T00:01:00+00:00",
                        ),
                    )
                    conn.commit()
                state_db.chmod(0o600)
                exact_payload = self.run_direct(
                    vault,
                    [retrieve.Candidate(str(target), "项目/事实-owner.md", 1)],
                    actor="test",
                    app_id="",
                    project_id="",
                    _observation_capability=retrieve._SYNTHETIC_BENCHMARK_CAPABILITY,
                )
                exact_item = exact_payload["results"][0]  # type: ignore[index]
                self.assertEqual(exact_item["metadata_gate_reason_codes"], [])
                self.assertFalse(exact_item["metadata_gate_would_block"])
                self.assertTrue(exact_item["can_authorize_action"])

    def test_canonical_action_sensitive_shadow_reports_atomic_gaps_even_if_already_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "sensitive.md"
            target.write_text(
                "---\n"
                f"memory_id: {'a' * 64}\n"
                "memory_type: project\ntrack: project\n"
                "app_id: agent-memory\nproject_id: global\nagent_scope: shared\n"
                "status: active\nrisk_class: action_sensitive\n"
                "temporal_policy: reviewable\nreview_after_days: 90\n"
                "---\n# Sensitive\n\nretrievalprobe\n",
                encoding="utf-8",
            )
            real_projection = retrieve.shadow_gate.metadata_gate_projection

            def shadow_projection(reason_sets: object) -> dict[str, object]:
                return real_projection(
                    reason_sets,  # type: ignore[arg-type]
                    config={"observability": {"metadata_enforcement": "shadow"}},
                )

            with mock.patch.object(
                retrieve.shadow_gate,
                "metadata_gate_projection",
                side_effect=shadow_projection,
            ):
                payload = self.run_direct(
                    vault,
                    [retrieve.Candidate(str(target), "项目/sensitive.md", 1)],
                    actor="test",
                    app_id="",
                    project_id="",
                    _observation_capability=retrieve._SYNTHETIC_BENCHMARK_CAPABILITY,
                )
        item = payload["results"][0]  # type: ignore[index]
        self.assertEqual(item["metadata_gate_mode"], "shadow")
        self.assertEqual(
            set(item["metadata_gate_reason_codes"]),
            {
                "METADATA_ATOMIC_FACT_KEY_INVALID",
                "METADATA_ATOMIC_VALID_FROM_INVALID",
                "METADATA_ATOMIC_VERIFIED_AT_INVALID",
                "METADATA_CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
            },
        )
        self.assertTrue(item["metadata_gate_would_block"])
        self.assertFalse(item["can_authorize_action"])

    def test_live_frontmatter_cannot_masquerade_as_governance_or_misc(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "masquerade.md"
            target.write_text(
                "---\nmemory_type: governance\ntrack: misc\napp_id: \n"
                "project_id: global\nagent_scope: shared\nstatus: active\n"
                "risk_class: ordinary\ntemporal_policy: structural\n"
                "review_after_days: 90\n---\n# masquerade retrievalprobe\n",
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [retrieve.Candidate(str(target), "项目/masquerade.md", 1)],
                actor="test",
                app_id="",
                project_id="",
            )
            item = payload["results"][0]  # type: ignore[index]
            self.assertTrue(item["analogy_only"])
            self.assertFalse(item["can_authorize_action"])
            self.assertTrue(item["requires_live_verification"])
            self.assertEqual(
                set(item["path_policy_reason_codes"]),
                {"PATH_TRACK_DOWNGRADE", "PATH_MEMORY_TYPE_DOWNGRADE"},
            )
            self.assertIn(
                "path_policy_downgrade_reference_only",
                item["policy"]["warnings"],
            )

    def test_canonical_risk_downgrade_is_reference_only_and_shadow_observed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            decisions = vault / "决策"
            decisions.mkdir(parents=True)
            target = decisions / "owner.md"
            target.write_text(
                "---\nmemory_id: " + "a" * 64 + "\n"
                "memory_type: decision\ntrack: decision\nproject_id: global\n"
                "app_id: agent-memory\nagent_scope: shared\nstatus: active\n"
                "risk_class: ordinary\ntemporal_policy: reviewable\nreview_after_days: 90\n"
                "verification_mode: structural\n---\n# Decision\n\nretrievalprobe\n",
                encoding="utf-8",
            )
            projection = {
                "configured_mode": "shadow",
                "effective_mode": "shadow",
                "would_block_count": 1,
                "reason_codes": ["METADATA_RISK_CLASS_DOWNGRADE"],
                "reason_fingerprint": "b" * 64,
                "enforced": False,
            }
            with mock.patch.object(
                retrieve.shadow_gate,
                "metadata_gate_projection",
                return_value=projection,
            ) as projected:
                payload = self.run_direct(
                    vault,
                    [retrieve.Candidate(str(target), "决策/owner.md", 1)],
                    actor="test",
                    app_id="",
                    project_id="",
                )
        item = payload["results"][0]  # type: ignore[index]
        expected_reasons = (
            "METADATA_RISK_CLASS_DOWNGRADE",
            "METADATA_ATOMIC_FACT_KEY_INVALID",
            "METADATA_ATOMIC_VALID_FROM_INVALID",
            "METADATA_ATOMIC_VERIFIED_AT_INVALID",
            "METADATA_CURRENT_CONTENT_EVIDENCE_RECEIPT_MISSING",
        )
        projected.assert_called_once_with([expected_reasons])
        self.assertEqual(item["risk_class"], "ordinary")
        self.assertEqual(item["risk_class_source"], "frontmatter")
        self.assertIn("RISK_CLASS_DOWNGRADE", item["path_policy_reason_codes"])
        self.assertEqual(
            item["metadata_gate_reason_codes"],
            list(expected_reasons),
        )
        self.assertTrue(item["metadata_gate_would_block"])
        self.assertTrue(item["analogy_only"])
        self.assertFalse(item["can_authorize_action"])

    def test_canonical_pending_verification_is_visible_but_never_authorizes(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "pending.md"
            target.write_text(
                "---\nmemory_id: " + "a" * 64 + "\n"
                "memory_type: project\ntrack: project\nproject_id: global\n"
                "app_id: agent-memory\nagent_scope: shared\nstatus: pending_verification\n"
                "risk_class: ordinary\ntemporal_policy: reviewable\nreview_after_days: 90\n"
                "verification_mode: structural\n---\n# Pending\n\nretrievalprobe\n",
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [retrieve.Candidate(str(target), "项目/pending.md", 1)],
                actor="test",
                app_id="",
                project_id="",
            )
        item = payload["results"][0]  # type: ignore[index]
        self.assertEqual(item["policy"]["status"], "pending_verification")
        self.assertFalse(item["metadata_gate_would_block"])
        self.assertEqual(item["metadata_gate_reason_codes"], [])
        self.assertFalse(item["can_authorize_action"])

    def test_canonical_retrieve_records_an_independent_privacy_safe_search_denominator(self) -> None:
        result = {
            "relative_path": "项目/example.md",
            "memory_id": "a" * 64,
            "requires_live_verification": False,
        }
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        projection = {
            "effective_mode": "shadow",
            "would_block_count": 1,
            "reason_fingerprint": "b" * 64,
        }
        with (
            mock.patch.object(retrieve.memory_search, "connect", return_value=connection),
            mock.patch.object(
                retrieve.observability,
                "record_search",
                return_value="search-id",
            ) as recorded,
        ):
            identifier = retrieve._record_canonical_retrieve_search(
                "private query",
                [result],
                duration_ms=17,
                search_status="success",
                search_metadata={
                    "ranking_mode": "hybrid-v2-shadow",
                    "backend_status": {
                        "worker_status": "reused",
                        "worker_restart_count": 0,
                    },
                    "degraded": False,
                },
                metadata_projection=projection,
            )
        self.assertEqual(identifier, "search-id")
        kwargs = recorded.call_args.kwargs
        self.assertEqual(kwargs["sources"], ["canonical_retrieve"])
        self.assertEqual(kwargs["ranking_mode"], "shadow")
        self.assertEqual(kwargs["metadata_gate_mode"], "shadow")
        self.assertEqual(kwargs["metadata_would_block_count"], 1)
        self.assertNotIn("private query", repr(connection.mock_calls))

    def test_required_and_total_candidate_backend_failures_propagate(self) -> None:
        def required_failure(namespace: object):
            setattr(namespace, "_hard_failure", True)
            setattr(namespace, "_failure_reason_code", search.RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE)
            return [], ["semantic unavailable"], False

        with mock.patch.object(search, "run_search", side_effect=required_failure):
            with self.assertRaises(retrieve.RetrievalProtocolError) as caught:
                retrieve.search_candidates(
                    "query",
                    5,
                    actor="codex",
                    semantic_mode="required",
                )
        self.assertEqual(
            caught.exception.code,
            search.RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE,
        )

        with mock.patch.object(search, "run_search", return_value=([], ["all failed"], True)):
            with self.assertRaises(retrieve.RetrievalProtocolError) as caught:
                retrieve.search_candidates("query", 5, actor="codex", semantic_mode="auto")
        self.assertEqual(caught.exception.code, search.RETRIEVAL_BACKENDS_UNAVAILABLE)

        for semantic_mode, expected in (
            ("auto", search.RETRIEVAL_BACKENDS_UNAVAILABLE),
            ("required", search.RETRIEVAL_BACKEND_REQUIRED_UNAVAILABLE),
        ):
            with self.subTest(semantic_mode=semantic_mode), mock.patch.object(
                search,
                "run_search",
                side_effect=RuntimeError("private backend detail must not escape"),
            ):
                with self.assertRaises(retrieve.RetrievalProtocolError) as caught:
                    retrieve.search_candidates(
                        "query",
                        5,
                        actor="codex",
                        semantic_mode=semantic_mode,
                    )
                self.assertEqual(caught.exception.code, expected)
                self.assertNotIn("private backend detail", str(caught.exception))

    def test_auto_partial_candidate_backend_failure_remains_degraded(self) -> None:
        lexical = search.SearchResult(
            path="/vault/项目/example.md",
            rel_path="项目/example.md",
            status="active",
        )

        def partial(namespace: object):
            setattr(namespace, "_effective_ranking_version", "hybrid-v1")
            setattr(namespace, "_backend_status", {"unicode_fts": "ok", "zvec": "failed"})
            setattr(namespace, "_degraded", True)
            return [lexical], ["semantic unavailable"], False

        with mock.patch.object(search, "run_search", side_effect=partial):
            candidates, warnings, metadata = retrieve.search_candidates(
                "query",
                5,
                actor="codex",
                semantic_mode="auto",
            )
        self.assertEqual([item.rel_path for item in candidates], ["项目/example.md"])
        self.assertTrue(metadata["degraded"])
        self.assertEqual(metadata["ranking_version"], "hybrid-v1")
        self.assertEqual(warnings[0]["code"], "SEARCH_BACKEND_WARNING")

    def test_canonical_inactive_policy_only_includes_outdated_and_archived(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            candidates: list[retrieve.Candidate] = []
            for rank, status in enumerate(
                ("active", "pending_verification", "outdated", "archived", "candidate", "stale"),
                1,
            ):
                target = project / f"{status}.md"
                target.write_text(
                    markdown(status, project_id="global", status=status),
                    encoding="utf-8",
                )
                candidates.append(
                    retrieve.Candidate(str(target), f"项目/{status}.md", rank)
                )
            payload = self.run_direct(
                vault,
                candidates,
                actor="test",
                app_id="",
                project_id="",
                include_inactive=True,
            )
            by_path = {
                item["relative_path"]: item
                for item in payload["results"]  # type: ignore[index]
            }
            self.assertEqual(
                set(by_path),
                {
                    "项目/active.md",
                    "项目/pending_verification.md",
                    "项目/outdated.md",
                    "项目/archived.md",
                },
            )
            for status in ("pending_verification", "outdated", "archived"):
                self.assertFalse(by_path[f"项目/{status}.md"]["can_authorize_action"])
            reasons = {
                warning.get("relative_path"): warning.get("reason")
                for warning in payload["warnings"]  # type: ignore[index]
            }
            self.assertEqual(reasons["项目/candidate.md"], "STATUS_NOT_ACTIVE")
            self.assertEqual(reasons["项目/stale.md"], "STATUS_NOT_ACTIVE")

    def test_canonical_inactive_history_does_not_require_a_second_fact_flag(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            specifications = (
                ("outdated", "outdated", "superseded"),
                ("archived", "archived", "historical"),
                ("active-history", "active", "superseded"),
                ("candidate-history", "candidate", "historical"),
            )
            candidates: list[retrieve.Candidate] = []
            fact_statuses: dict[str, str] = {}
            for rank, (name, status, fact_status) in enumerate(specifications, 1):
                target = project / f"{name}.md"
                target.write_text(
                    markdown(name, project_id="project-a", status=status),
                    encoding="utf-8",
                )
                relative = f"项目/{name}.md"
                candidates.append(retrieve.Candidate(str(target), relative, rank))
                fact_statuses[relative] = fact_status

            def temporal_policy(
                rel_path: str,
                _raw_text: str,
                _metadata: dict[str, object],
                _as_of: object,
            ) -> dict[str, str]:
                return {
                    "fact_key": "fixture.fact",
                    "valid_from": "2026-01-01",
                    "fact_status": fact_statuses[rel_path],
                    "current_fact_path": "",
                    "superseded_by": "",
                    "superseded_at": "",
                    "fact_reason_code": "",
                }

            with mock.patch.object(
                retrieve,
                "_canonical_temporal_policy",
                side_effect=temporal_policy,
            ):
                payload = self.run_direct(
                    vault,
                    candidates,
                    actor="test",
                    app_id="",
                    project_id="",
                    current_project="project-a",
                    include_inactive=True,
                )
            by_path = {
                item["relative_path"]: item
                for item in payload["results"]  # type: ignore[index]
            }
            self.assertEqual(
                set(by_path),
                {"项目/outdated.md", "项目/archived.md"},
            )
            self.assertEqual(by_path["项目/outdated.md"]["fact_status"], "superseded")
            self.assertEqual(by_path["项目/archived.md"]["fact_status"], "historical")
            for item in by_path.values():
                self.assertFalse(item["can_authorize_action"])
                self.assertFalse(item["canonical_read_required"])
                self.assertIn("inactive_or_historical_memory", item["policy"]["warnings"])
            reasons = {
                warning.get("relative_path"): warning.get("reason")
                for warning in payload["warnings"]  # type: ignore[index]
            }
            self.assertEqual(
                reasons["项目/active-history.md"],
                "FACT_SUPERSEDED",
            )
            self.assertEqual(
                reasons["项目/candidate-history.md"],
                "STATUS_NOT_ACTIVE",
            )

    def test_codex_style_current_project_context_preserves_canonical_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "current.md"
            target.write_text(
                markdown("current", app_id="", project_id="project-a"),
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [retrieve.Candidate(str(target), "项目/current.md", 1)],
                actor="test",
                app_id="",
                project_id="",
                current_project="project-a",
            )
            item = payload["results"][0]  # type: ignore[index]
            self.assertEqual(item["scope_status"], "current_project")
            self.assertFalse(item["analogy_only"])
            self.assertTrue(item["can_authorize_action"])

    def test_single_oversized_outline_title_is_utf8_safely_shortened(self) -> None:
        heading = retrieve.Heading(
            section_id="s0001",
            level=1,
            title="中文标题" * 500,
            parent_section_id="",
            start_line=1,
            end_line=1,
            start_char=0,
            end_char=2000,
            start_byte=0,
            end_byte=6000,
        )
        page, truncated, next_offset, returned_bytes = retrieve._outline_page(
            [heading], max_bytes=320, offset=0
        )
        encoded = json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertEqual(returned_bytes, len(encoded))
        self.assertLessEqual(returned_bytes, 320)
        self.assertTrue(page[0]["title_truncated"])
        self.assertTrue(page[0]["title"])
        self.assertFalse(truncated)
        self.assertIsNone(next_offset)

    def test_outline_offsets_are_source_byte_offsets_for_bom_and_crlf(self) -> None:
        source = "\ufeff---\r\n# yaml comment\r\n---\r\n# 标题\r\n正文\r\n"
        headings = retrieve._markdown_headings(source)
        self.assertEqual(len(headings), 1)
        heading = headings[0]
        self.assertEqual(heading.title, "标题")
        self.assertEqual(source[heading.start_char : heading.end_char], "# 标题\r\n正文\r\n")
        encoded = source.encode("utf-8")
        self.assertEqual(encoded[heading.start_byte : heading.end_byte], "# 标题\r\n正文\r\n".encode("utf-8"))

    def test_section_view_requires_cas_and_valid_pagination_options(self) -> None:
        base = {
            "actor": "codex",
            "app_id": "",
            "project_id": "",
            "query": "",
            "max_results": 1,
            "max_file_bytes": 1024,
            "max_total_bytes": 1024,
            "max_excerpt_bytes": 32,
            "view": "section",
            "file_path": "项目/example.md",
        }
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            vault.mkdir()
            with mock.patch.object(retrieve, "VAULT_ROOT", vault):
                for overrides, code in (
                    ({"section_id": "", "expected_sha256": "a" * 64}, "SECTION_ID_REQUIRED"),
                    ({"section_id": "s0001", "expected_sha256": "bad"}, "EXPECTED_SHA256_REQUIRED"),
                    (
                        {
                            "section_id": "s0001",
                            "expected_sha256": "a" * 64,
                            "offset_chars": -1,
                        },
                        "OFFSET_INVALID",
                    ),
                ):
                    with self.subTest(code=code):
                        with self.assertRaisesRegex(retrieve.RetrievalProtocolError, code):
                            retrieve.retrieve(**base, **overrides)  # type: ignore[arg-type]

    def test_internal_benchmark_capability_preserves_scope_but_suppresses_real_observations(self) -> None:
        base = {
            "actor": "codex",
            "app_id": "",
            "project_id": "",
            "query": "benchmark query",
            "max_results": 5,
            "max_file_bytes": 1024,
            "max_total_bytes": 4096,
            "max_excerpt_bytes": 512,
            "candidates": [],
        }
        projection = {
            "effective_mode": "shadow",
            "would_block_count": 0,
            "reason_fingerprint": "",
            "enforced": False,
        }
        with (
            mock.patch.object(retrieve, "validate_vault_root"),
            mock.patch.object(retrieve, "current_git_head", return_value=("a" * 40, None)),
            mock.patch.object(retrieve.shadow_gate, "metadata_gate_projection", return_value=projection),
            mock.patch.object(retrieve, "_record_canonical_retrieve_search", return_value="search") as search,
            mock.patch.object(retrieve, "_record_source_opened_events", return_value=[]) as opened,
        ):
            synthetic = retrieve.retrieve(
                **base,
                _observation_capability=retrieve._SYNTHETIC_BENCHMARK_CAPABILITY,
            )
            search.assert_not_called()
            opened.assert_not_called()
            self.assertEqual(synthetic["actor"], "codex")
            self.assertFalse(synthetic["observation"]["automatic"])
            self.assertTrue(synthetic["observation"]["synthetic_benchmark"])

            # Merely passing an arbitrary value cannot forge the identity-only
            # in-process capability used by the benchmark module.
            ordinary = retrieve.retrieve(**base, _observation_capability=object())
            search.assert_called_once()
            opened.assert_called_once()
            self.assertTrue(ordinary["observation"]["automatic"])
            self.assertFalse(ordinary["observation"]["synthetic_benchmark"])

    def test_ailu_scope_request_requires_fixed_app_and_safe_project(self) -> None:
        for app_id, project_id, reason in (
            ("", "", "APP_ID_REQUIRED"),
            ("other-app", "", "APP_ID_UNSUPPORTED"),
            ("ailu", "", "PROJECT_ID_REQUIRED"),
            ("ailu", "one,two", "PROJECT_ID_INVALID"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaises(retrieve.RetrievalProtocolError) as raised:
                    retrieve.validate_ailu_scope_request(app_id, project_id)
                self.assertEqual(raised.exception.code, reason)

    def test_ailu_cli_rejects_private_query_in_argv(self) -> None:
        private_query = "private-query-must-not-reach-child-94731"
        completed = subprocess.run(
            [
                str(SCRIPTS / "memoryctl"),
                "--actor",
                "ailu",
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

    def test_ailu_actor_is_accepted_without_inheriting_codex_session(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            [
                "agent_memory_claim.py",
                "--actor",
                "ailu",
                "--session-id",
                "plugin-session",
                "list",
            ],
        ):
            self.assertEqual(memory_claim.parse_args().actor, "ailu")
        with mock.patch.object(
            sys,
            "argv",
            [
                "agent_memory_intent.py",
                "--actor",
                "ailu",
                "--session-id",
                "plugin-session",
                "show",
                "--intent-id",
                "example",
            ],
        ):
            self.assertEqual(memory_intent.parse_args().actor, "ailu")
        with mock.patch.dict(
            os.environ,
            {"CODEX_THREAD_ID": "outer-codex-session"},
            clear=False,
        ):
            os.environ.pop("AGENT_MEMORY_SESSION_ID", None)
            self.assertEqual(memory_intent._session_value("", "ailu"), "")

    def run_direct(self, vault: Path, candidates: list[retrieve.Candidate], **overrides: object) -> dict[str, object]:
        resolved_vault = vault.resolve()
        defaults: dict[str, object] = {
            "actor": "ailu",
            "app_id": "ailu",
            "project_id": "ailu",
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
            payload = self.run_direct(
                vault,
                candidates,
                actor="codex",
                app_id="",
                project_id="",
                max_total_bytes=budget,
            )
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

    def test_duplicate_authorization_frontmatter_keys_fail_closed(self) -> None:
        duplicate_values = {
            "risk_class": ("action_sensitive", "ordinary"),
            "temporal_policy": ("reviewable", "structural"),
            "fact_key": ("project.owner", "project.other_owner"),
            "valid_from": ("2026-08-01", "2026-08-02"),
            "valid_until": ("2026-09-01", "2026-09-02"),
            "verified_at": ("2026-08-01", "2026-08-02"),
        }
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            for key, values in duplicate_values.items():
                with self.subTest(key=key):
                    duplicate = project / f"duplicate-{key}.md"
                    duplicate.write_text(
                        "---\n"
                        f"memory_id: {'a' * 64}\n"
                        "memory_type: fact\ntrack: project\n"
                        "app_id: ailu\nproject_id: ailu\nagent_scope: shared\n"
                        "status: active\nreview_after_days: 90\n"
                        f"{key}: {values[0]}\n{key}: {values[1]}\n"
                        "---\n# Duplicate\n\nretrievalprobe\n",
                        encoding="utf-8",
                    )
                    payload = self.run_direct(
                        vault,
                        [
                            retrieve.Candidate(
                                str(duplicate),
                                f"项目/duplicate-{key}.md",
                                1,
                            )
                        ],
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
                markdown("current", project_id="ailu"),
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [
                    retrieve.Candidate(str(global_file), "项目/global.md", 1),
                    retrieve.Candidate(str(current_file), "项目/current.md", 2),
                ],
                actor="codex",
                app_id="",
                project_id="",
                max_excerpt_bytes=31,
            )
            self.assertEqual(
                [item["relative_path"] for item in payload["results"]],  # type: ignore[index]
                ["项目/global.md", "项目/current.md"],
            )
            item = payload["results"][0]  # type: ignore[index]
            self.assertTrue(item["excerpt_truncated"])
            self.assertLessEqual(len(item["excerpt"].encode("utf-8")), 31)
            self.assertNotIn("query", payload)
            self.assertEqual(payload["results"][1]["scope_status"], "project_context_unknown")  # type: ignore[index]
            self.assertTrue(payload["results"][1]["analogy_only"])  # type: ignore[index]
            self.assertFalse(payload["results"][1]["can_authorize_action"])  # type: ignore[index]

    def test_current_markdown_review_due_policy_respects_explicit_as_of(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "reviewable.md"
            target.write_text(
                markdown(
                    "reviewable",
                    verified_at="2026-06-01",
                    review_after_days=30,
                    valid_until="2026-12-31",
                ),
                encoding="utf-8",
            )
            candidate = retrieve.Candidate(str(target), "项目/reviewable.md", 1)

            due_today = self.run_direct(
                vault,
                [candidate],
                actor="test",
                app_id="",
                project_id="",
                as_of="2026-07-01",
            )
            due_item = due_today["results"][0]  # type: ignore[index]
            self.assertEqual(due_today["as_of"], "2026-07-01")
            self.assertEqual(due_item["policy"]["review_status"], "due_today")
            self.assertEqual(due_item["policy"]["review_due_at"], "2026-07-01")
            self.assertEqual(due_today["as_of_status"], "historical")
            self.assertTrue(due_item["analogy_only"])
            self.assertFalse(due_item["can_authorize_action"])
            self.assertTrue(due_item["requires_live_verification"])
            self.assertIn(
                "historical_as_of_reference_only",
                due_item["policy"]["warnings"],
            )

            overdue = self.run_direct(
                vault,
                [candidate],
                actor="test",
                app_id="",
                project_id="",
                as_of="2026-07-02",
            )
            item = overdue["results"][0]  # type: ignore[index]
            self.assertEqual(overdue["as_of"], "2026-07-02")
            self.assertEqual(item["policy"]["time_status"], "current")
            self.assertEqual(item["policy"]["review_after_days"], 30)
            self.assertEqual(item["policy"]["review_status"], "overdue")
            self.assertEqual(item["policy"]["review_due_at"], "2026-07-01")
            self.assertEqual(
                item["policy"]["warnings"],
                [search.REVIEW_OVERDUE_WARNING, "historical_as_of_reference_only"],
            )
            self.assertTrue(item["policy"]["requires_live_verification"])
            self.assertTrue(item["requires_live_verification"])

    def test_explicit_expiry_precedes_review_overdue_in_current_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "expired.md"
            target.write_text(
                markdown(
                    "expired",
                    verified_at="2026-01-01",
                    review_after_days=30,
                    valid_until="2026-02-01",
                ),
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [retrieve.Candidate(str(target), "项目/expired.md", 1)],
                actor="test",
                app_id="",
                project_id="",
                as_of="2026-03-01",
            )
            item = payload["results"][0]  # type: ignore[index]
            self.assertEqual(item["policy"]["time_status"], "expired")
            self.assertEqual(item["policy"]["review_status"], "overdue")
            self.assertEqual(
                item["live_verification"]["reasons"],
                [
                    "expired_memory_reference_only",
                    search.REVIEW_OVERDUE_WARNING,
                    "historical_as_of_reference_only",
                ],
            )

    def test_malformed_valid_until_is_reference_only_in_canonical_retrieve(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "malformed-date.md"
            target.write_text(
                markdown(
                    "malformed-date",
                    project_id="global",
                    valid_until="2099-01-01junk",
                    verification_mode="structural",
                ),
                encoding="utf-8",
            )
            payload = self.run_direct(
                vault,
                [retrieve.Candidate(str(target), "项目/malformed-date.md", 1)],
                actor="test",
                app_id="",
                project_id="",
                as_of="2026-08-24",
            )
            item = payload["results"][0]  # type: ignore[index]
            self.assertEqual(item["policy"]["time_status"], "invalid")
            self.assertIn("invalid_valid_until", item["live_verification"]["reasons"])
            self.assertTrue(item["requires_live_verification"])
            self.assertFalse(item["can_authorize_action"])

    def test_structural_snapshot_and_missing_verification_are_not_review_overdue(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            candidates: list[retrieve.Candidate] = []
            for rank, (name, mode) in enumerate(
                (("structural", "structural"), ("snapshot", "snapshot"), ("unverified", "")),
                1,
            ):
                target = project / f"{name}.md"
                target.write_text(
                    markdown(
                        name,
                        verified_at="",
                        review_after_days=1,
                        verification_mode=mode,
                    ),
                    encoding="utf-8",
                )
                candidates.append(retrieve.Candidate(str(target), f"项目/{name}.md", rank))

            payload = self.run_direct(
                vault,
                candidates,
                actor="test",
                app_id="",
                project_id="",
                as_of="2030-01-01",
            )
            by_path = {
                item["relative_path"]: item
                for item in payload["results"]  # type: ignore[index]
            }
            for name in ("structural", "snapshot"):
                item = by_path[f"项目/{name}.md"]
                self.assertEqual(item["policy"]["review_status"], "not_applicable")
                self.assertNotIn(search.REVIEW_OVERDUE_WARNING, item["policy"]["warnings"])
                self.assertTrue(item["requires_live_verification"])
                self.assertTrue(item["analogy_only"])
                self.assertFalse(item["can_authorize_action"])
                self.assertIn(
                    "historical_as_of_reference_only",
                    item["policy"]["warnings"],
                )

            unverified = by_path["项目/unverified.md"]
            self.assertEqual(unverified["policy"]["review_status"], "unverified")
            self.assertEqual(unverified["policy"]["review_due_at"], "")
            self.assertEqual(
                unverified["policy"]["warnings"],
                ["verification_needed", "historical_as_of_reference_only"],
            )
            self.assertNotIn(search.REVIEW_OVERDUE_WARNING, unverified["policy"]["warnings"])
            self.assertTrue(unverified["requires_live_verification"])

    def test_non_today_as_of_is_historical_and_ledger_never_records_current(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "historical.md"
            target.write_text(
                markdown("historical", app_id="", project_id="global"),
                encoding="utf-8",
            )
            candidate = retrieve.Candidate(str(target), "项目/historical.md", 1)
            historical_date = (dt.date.today() - dt.timedelta(days=1)).isoformat()
            with mock.patch.object(
                retrieve.observability,
                "record_opened_original",
                return_value="event-id",
            ) as recorded:
                payload = self.run_direct(
                    vault,
                    [candidate],
                    actor="test",
                    app_id="",
                    project_id="",
                    as_of=historical_date,
                )
            item = payload["results"][0]  # type: ignore[index]
            self.assertEqual(payload["as_of_status"], "historical")
            self.assertEqual(item["as_of_status"], "historical")
            self.assertTrue(item["analogy_only"])
            self.assertFalse(item["can_authorize_action"])
            self.assertTrue(item["requires_live_verification"])
            self.assertEqual(recorded.call_args.kwargs["policy_state"], "unknown")
            self.assertTrue(
                recorded.call_args.kwargs["requires_live_verification"]
            )

    def test_invalid_as_of_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            vault = Path(raw_root) / "vault"
            project = vault / "项目"
            project.mkdir(parents=True)
            target = project / "example.md"
            target.write_text(markdown("example"), encoding="utf-8")
            with self.assertRaisesRegex(retrieve.RetrievalProtocolError, "AS_OF_INVALID"):
                self.run_direct(
                    vault,
                    [retrieve.Candidate(str(target), "项目/example.md", 1)],
                    actor="test",
                    app_id="",
                    project_id="",
                    as_of="not-a-date",
                )

        with mock.patch.object(
            sys,
            "argv",
            [
                "agent_memory_retrieve.py",
                "retrievalprobe",
                "--actor",
                "test",
                "--as-of",
                "2026-07-02",
            ],
        ):
            self.assertEqual(retrieve.parse_args().as_of, "2026-07-02")

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
