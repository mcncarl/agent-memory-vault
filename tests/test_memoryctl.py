from __future__ import annotations

import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import venv
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import agent_memory_shadow as shadow_runtime


def load_memoryctl():
    path = SCRIPTS_ROOT / "memoryctl"
    loader = importlib.machinery.SourceFileLoader("test_memoryctl_module", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    # These are wrapper-routing tests, not installed-runtime transition tests.
    module.assert_runtime_ready = lambda _command, **_kwargs: {"ready": True}
    return module


def routed_target(command: list[object]) -> str:
    """Return the script argument from memoryctl's isolated runpy wrapper."""

    code_index = command.index("-c")
    return str(command[code_index + 2])


class MemoryctlInterpreterTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Ailu descriptor snapshots are POSIX-only")
    def test_ailu_valid_descriptor_snapshot_uses_canonical_runtime(self) -> None:
        module = load_memoryctl()
        script = SCRIPTS_ROOT / "memoryctl"
        digest = hashlib.sha256(script.read_bytes()).hexdigest()
        descriptor = os.open(script, os.O_RDONLY)
        try:
            descriptor_path = f"/dev/fd/{descriptor}"
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_MEMORY_AILU_RUNTIME_ROOT": str(REPO_ROOT),
                    "AGENT_MEMORY_AILU_ENTRYPOINT_SHA256": digest,
                },
            ):
                entrypoint, runtime_root = module._select_entry_identity(descriptor_path)
        finally:
            os.close(descriptor)
        self.assertEqual(entrypoint, script)
        self.assertEqual(runtime_root, REPO_ROOT)
        self.assertEqual(module._ailu_snapshot_descriptor("/proc/self/fd/7"), 7)

    @unittest.skipUnless(os.name == "posix", "Ailu descriptor snapshots are POSIX-only")
    def test_ailu_descriptor_snapshot_rejects_wrong_hash(self) -> None:
        module = load_memoryctl()
        script = SCRIPTS_ROOT / "memoryctl"
        descriptor = os.open(script, os.O_RDONLY)
        try:
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_MEMORY_AILU_RUNTIME_ROOT": str(REPO_ROOT),
                    "AGENT_MEMORY_AILU_ENTRYPOINT_SHA256": "0" * 64,
                },
            ), self.assertRaisesRegex(
                SystemExit,
                "RUNTIME_BOOTSTRAP_AILU_ENTRYPOINT_INTEGRITY_MISMATCH",
            ):
                module._select_entry_identity(f"/dev/fd/{descriptor}")
        finally:
            os.close(descriptor)

    @unittest.skipUnless(os.name == "posix", "Ailu descriptor snapshots are POSIX-only")
    def test_ailu_descriptor_snapshot_rejects_incomplete_environment(self) -> None:
        module = load_memoryctl()
        script = SCRIPTS_ROOT / "memoryctl"
        digest = hashlib.sha256(script.read_bytes()).hexdigest()
        descriptor = os.open(script, os.O_RDONLY)
        try:
            attempts = (
                (str(REPO_ROOT), None),
                (None, digest),
            )
            for runtime_root, expected_digest in attempts:
                with self.subTest(runtime_root=runtime_root is not None):
                    environment = {}
                    if runtime_root is not None:
                        environment["AGENT_MEMORY_AILU_RUNTIME_ROOT"] = runtime_root
                    if expected_digest is not None:
                        environment["AGENT_MEMORY_AILU_ENTRYPOINT_SHA256"] = expected_digest
                    with mock.patch.dict(os.environ, environment, clear=True), self.assertRaisesRegex(
                        SystemExit,
                        "RUNTIME_BOOTSTRAP_AILU_SNAPSHOT_ENV_INCOMPLETE",
                    ):
                        module._select_entry_identity(f"/dev/fd/{descriptor}")
        finally:
            os.close(descriptor)

    @unittest.skipUnless(os.name == "posix", "Ailu descriptor snapshots are POSIX-only")
    def test_ailu_snapshot_rejects_alternate_non_descriptor_path(self) -> None:
        module = load_memoryctl()
        script = SCRIPTS_ROOT / "memoryctl"
        raw = script.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            alternate = Path(temporary) / "memoryctl-snapshot"
            alternate.write_bytes(raw)
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_MEMORY_AILU_RUNTIME_ROOT": str(REPO_ROOT),
                    "AGENT_MEMORY_AILU_ENTRYPOINT_SHA256": hashlib.sha256(raw).hexdigest(),
                },
            ), self.assertRaisesRegex(
                SystemExit,
                "RUNTIME_BOOTSTRAP_AILU_ENTRYPOINT_PATH_INVALID",
            ):
                module._select_entry_identity(str(alternate))

    def test_recovery_queries_request_side_effect_free_readiness(self) -> None:
        for action, expected in (("status", True), ("list", True), ("read-target", False)):
            with self.subTest(action=action):
                module = load_memoryctl()
                readiness = mock.Mock(return_value={"ready": True})
                completed = subprocess.CompletedProcess([], 0)
                with (
                    mock.patch.object(module, "assert_runtime_ready", readiness),
                    mock.patch.object(module.subprocess, "run", return_value=completed),
                    mock.patch.object(
                        sys,
                        "argv",
                        ["memoryctl", "--actor", "ailu", "write", action, "--json"],
                    ),
                    mock.patch.dict(
                        os.environ,
                        {
                            "AGENT_MEMORY_SESSION_ID": "ailu-readiness-test",
                            "AGENT_MEMORY_OBSERVABILITY_ENABLED": "false",
                        },
                    ),
                ):
                    self.assertEqual(module.main(), 0)
                if expected:
                    readiness.assert_called_once_with(
                        "write",
                        side_effect_free_state=True,
                    )
                else:
                    readiness.assert_called_once_with("write")

    def test_user_guidance_uses_canonical_memoryctl_for_derived_maintenance(self) -> None:
        paths = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "README.zh-CN.md",
            REPO_ROOT / "scripts" / "bootstrap.py",
            REPO_ROOT / "templates" / "vault" / "工作流" / "Agent记忆语义检索设计.md",
            *sorted((REPO_ROOT / "docs").glob("*.md")),
        ]
        forbidden = re.compile(
            r"agent_memory_(?:index|zvec_index|retrieval_benchmark)\.py\s+--"
            r"|python3\s+scripts/memoryctl"
        )
        violations: list[str] = []
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for match in forbidden.finditer(text):
                violations.append(f"{path.relative_to(REPO_ROOT)}:{match.group(0)}")
        self.assertEqual(violations, [])

    def test_entrypoint_requires_isolated_and_no_site_flags(self) -> None:
        script = SCRIPTS_ROOT / "memoryctl"
        isolated_only = subprocess.run(
            [sys.executable, "-I", str(script), "--actor", "test", "version", "--json"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(isolated_only.returncode, 0)
        self.assertIn("MEMORYCTL_ISOLATED_LAUNCH_REQUIRED", isolated_only.stderr)
        isolated_no_site = subprocess.run(
            [sys.executable, "-I", "-S", str(script), "--actor", "test", "version", "--json"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotIn(
            "MEMORYCTL_ISOLATED_LAUNCH_REQUIRED",
            isolated_no_site.stdout + isolated_no_site.stderr,
        )

    def test_managed_launcher_is_derived_from_runtime_root_not_toml(self) -> None:
        module = load_memoryctl()
        expected = (
            module._ENTRY_ROOT / ".venv" / "Scripts" / "python.exe"
            if module.os.name == "nt"
            else module._ENTRY_ROOT / ".venv" / "bin" / "python"
        )
        self.assertEqual(module._managed_python_launcher(), expected)
        source = (SCRIPTS_ROOT / "memoryctl").read_text(encoding="utf-8")
        bootstrap = source.split("_reexec_with_managed_runtime_python()", 1)[0]
        # The private TOML may be used only as a non-executable footprint that
        # prevents a damaged managed Runtime from downgrading to source mode;
        # it must never select or configure the interpreter.
        self.assertNotIn("config_text", bootstrap)
        self.assertNotIn("tomllib", bootstrap)
        self.assertNotIn("runtime_python =", bootstrap)

    def test_launcher_comparison_is_lexical_not_resolved_base(self) -> None:
        module = load_memoryctl()
        launcher = module._managed_python_launcher()
        self.assertEqual(module._lexical_path(launcher), module._lexical_path(str(launcher)))
        self.assertNotEqual(
            module._lexical_path(launcher),
            module._lexical_path("/opt/base-python/bin/python3"),
        )

    def test_managed_bootstrap_authenticates_imported_modules_before_exec(self) -> None:
        module = load_memoryctl()
        content = {
            "scripts/memoryctl": b"entry",
            "scripts/agent_memory_env.py": b"env",
            "scripts/agent_memory_state.py": b"state",
            "scripts/agent_memory_migrate.py": b"migrate",
            "scripts/agent_memory_doctor.py": b"doctor",
            "requirements-vector.lock": b"support",
            "templates/vault/INDEX.md": b"template",
        }
        file_hashes = {
            Path(name).name: hashlib.sha256(raw).hexdigest()
            for name, raw in content.items()
            if name.startswith("scripts/")
        }
        anchor = {
            "schema_version": 1,
            "managed_runtime": True,
            "runtime_root": str(module._ENTRY_ROOT),
            "install_id": "1" * 64,
        }
        anchor_raw = (json.dumps(anchor, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        manifest = {
            "schema_version": 2,
            "release_version": module._RUNTIME_RELEASE_VERSION,
            "runtime_api_version": 2,
            "writer_protocol_version": 2,
            "state_schema_required": module.STATE_SCHEMA_REQUIRED,
            "canonical_actors": ["codex", "claude", "ailu"],
            "capabilities": {"write_gateway": module._WRITE_GATEWAY_CAPABILITIES},
            "runtime_root": str(module._ENTRY_ROOT),
            "install_id": anchor["install_id"],
            "runtime_anchor_sha256": hashlib.sha256(anchor_raw).hexdigest(),
            "files": file_hashes,
            "support_files": {"requirements-vector.lock": hashlib.sha256(content["requirements-vector.lock"]).hexdigest()},
            "template_files": {"templates/vault/INDEX.md": hashlib.sha256(content["templates/vault/INDEX.md"]).hexdigest()},
        }
        manifest["bundle_sha256"] = hashlib.sha256(
            json.dumps(
                {key: manifest[key] for key in ("files", "support_files", "template_files")},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        marker = {
            "schema_version": 1,
            "phase": "state_migration_required",
            "bundle_sha256": manifest["bundle_sha256"],
            "install_id": anchor["install_id"],
            "runtime_anchor_sha256": manifest["runtime_anchor_sha256"],
            "bootstrap_attestation": {"runtime_python": {"schema_version": 1}},
        }

        def secure_read(relative, *, optional=False):
            key = relative.as_posix()
            if key == "config/runtime-manifest.json":
                return json.dumps(manifest).encode("utf-8")
            if key == "config/runtime-transition.json":
                return json.dumps(marker).encode("utf-8")
            if key == "config/runtime-anchor.json":
                return anchor_raw
            return content[key]

        with mock.patch.object(module, "_secure_bootstrap_read", side_effect=secure_read):
            self.assertIsNotNone(module._managed_bootstrap_attestation())
        tampered = dict(content)
        tampered["scripts/agent_memory_env.py"] = b"tampered"

        def tampered_read(relative, *, optional=False):
            key = relative.as_posix()
            if key == "config/runtime-manifest.json":
                return json.dumps(manifest).encode("utf-8")
            if key == "config/runtime-transition.json":
                return json.dumps(marker).encode("utf-8")
            if key == "config/runtime-anchor.json":
                return anchor_raw
            return tampered[key]

        with mock.patch.object(module, "_secure_bootstrap_read", side_effect=tampered_read), self.assertRaisesRegex(
            SystemExit, "RUNTIME_BOOTSTRAP_INTEGRITY_MISMATCH"
        ):
            module._managed_bootstrap_attestation()

    def test_nonready_full_bundle_tamper_blocks_before_any_exec(self) -> None:
        module = load_memoryctl()
        managed = mock.Mock()
        with mock.patch.object(
            module,
            "_managed_bootstrap_attestation",
            side_effect=SystemExit("RUNTIME_BOOTSTRAP_INTEGRITY_MISMATCH"),
        ), mock.patch.object(module.os, "execve") as invoked, self.assertRaisesRegex(
            SystemExit, "RUNTIME_BOOTSTRAP_INTEGRITY_MISMATCH"
        ):
            module._reexec_with_managed_runtime_python()
        invoked.assert_not_called()

    def test_managed_python_attestation_mutations_block_pre_exec(self) -> None:
        module = load_memoryctl()
        actual = {
            "launcher": str(module._managed_python_launcher()),
            "launcher_chain": [{
                "path": ".venv/bin/python",
                "kind": "symlink",
                "link_target": "python3",
                "identity": {"device": 1, "inode": 7, "mode": 511, "size": 7, "mtime_ns": 8},
            }],
            "resolved_path": "/opt/python/bin/python3",
            "resolved_sha256": "a" * 64,
            "resolved_identity": {"device": 1, "inode": 2, "mode": 493, "size": 3, "mtime_ns": 4},
        }
        expected = {
            "schema_version": 1,
            **actual,
            "version": [3, 12, 1],
            "implementation": "CPython",
            "probe_executable": str(module._managed_python_launcher()),
            "base_prefix": "/opt/python",
        }
        expected["attestation_sha256"] = hashlib.sha256(
            json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        for key, value in (
            ("launcher", "/tampered/python"),
            ("launcher_chain", [{"path": ".venv/bin/python", "kind": "symlink", "link_target": "evil"}]),
            ("resolved_sha256", "b" * 64),
            ("resolved_identity", {"device": 9}),
        ):
            candidate = dict(actual)
            candidate[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                SystemExit, "RUNTIME_BOOTSTRAP_PYTHON_ATTESTATION_MISMATCH"
            ):
                module._validate_static_runtime_python(expected, candidate)
        malformed = dict(expected)
        malformed["attestation_sha256"] = "0" * 64
        with self.assertRaisesRegex(SystemExit, "RUNTIME_BOOTSTRAP_PYTHON_ATTESTATION_MISMATCH"):
            module._validate_static_runtime_python(malformed, actual)
        module._validate_static_runtime_python(expected, actual)
        renumbered = json.loads(json.dumps(actual))
        renumbered["launcher_chain"][0]["identity"]["device"] = 9
        renumbered["resolved_identity"]["device"] = 9
        with mock.patch.object(module.sys, "platform", "darwin"):
            module._validate_static_runtime_python(expected, renumbered)
            wrong_inode = json.loads(json.dumps(renumbered))
            wrong_inode["resolved_identity"]["inode"] = 99
            with self.assertRaisesRegex(
                SystemExit, "RUNTIME_BOOTSTRAP_PYTHON_ATTESTATION_MISMATCH"
            ):
                module._validate_static_runtime_python(expected, wrong_inode)
        with mock.patch.object(module.sys, "platform", "linux"), self.assertRaisesRegex(
            SystemExit, "RUNTIME_BOOTSTRAP_PYTHON_ATTESTATION_MISMATCH"
        ):
            module._validate_static_runtime_python(expected, renumbered)

    def test_missing_managed_identity_never_downgrades_target_layout_to_source(self) -> None:
        module = load_memoryctl()
        original_root = module._ENTRY_ROOT
        runtime = mock.MagicMock()
        runtime.__truediv__.side_effect = lambda *_args: runtime
        runtime.exists.return_value = True
        runtime.is_symlink.return_value = False
        with mock.patch.object(module, "_ENTRY_ROOT", runtime), mock.patch.object(
            module, "_secure_bootstrap_read", return_value=None
        ), self.assertRaisesRegex(SystemExit, "RUNTIME_BOOTSTRAP_IDENTITY_MISSING"):
            module._managed_bootstrap_attestation()
        module._ENTRY_ROOT = original_root

    def test_toml_only_managed_footprint_never_downgrades_to_source(self) -> None:
        module = load_memoryctl()

        def exists(path: Path) -> bool:
            return str(path).endswith("/config/agent-memory.toml")

        with mock.patch.object(
            module,
            "_secure_bootstrap_read",
            return_value=None,
        ), mock.patch.object(Path, "exists", exists), mock.patch.object(
            Path,
            "is_symlink",
            return_value=False,
        ), self.assertRaisesRegex(SystemExit, "RUNTIME_BOOTSTRAP_IDENTITY_MISSING"):
            module._managed_bootstrap_attestation()

    def test_observe_forwards_actor_to_privacy_boundary(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "claude", "observe", "current", "--json"],
            ),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 0)
        command = invoked.call_args.args[0]
        self.assertTrue(routed_target(command).endswith("agent_memory_observability.py"))
        self.assertEqual(command[-4:], ["--actor", "claude", "--json", "current"])

    def test_shadow_routes_status_and_requires_migration_for_mutation(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.object(
            sys, "argv", ["memoryctl", "--actor", "codex", "shadow", "status", "--json"]
        ), mock.patch.object(module.subprocess, "run", return_value=completed) as invoked:
            self.assertEqual(module.main(), 0)
        command = invoked.call_args.args[0]
        self.assertTrue(routed_target(command).endswith("agent_memory_shadow.py"))
        self.assertEqual(command[-4:], ["--actor", "codex", "--json", "status"])
        self.assertEqual(command.count("--actor"), 1)

    def test_shadow_top_level_help_is_safe_and_does_not_require_migration_actor(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        for flag in ("--help", "-h"):
            with self.subTest(flag=flag), mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "codex", "shadow", flag],
            ), mock.patch.object(
                module.subprocess,
                "run",
                return_value=completed,
            ) as invoked:
                self.assertEqual(module.main(), 0)
            command = invoked.call_args.args[0]
            self.assertTrue(
                routed_target(command).endswith("agent_memory_shadow.py")
            )
            self.assertEqual(command[-3:], ["--actor", "codex", flag])
            self.assertEqual(command.count("--actor"), 1)

        with mock.patch.object(
            sys, "argv", ["memoryctl", "--actor", "codex", "shadow", "cutover", "--config-backup", "/private/new"]
        ), mock.patch.object(module.subprocess, "run") as rejected, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(module.main(), 2)
            rejected.assert_not_called()

        restart_args = [
            "shadow",
            "restart",
            "--benchmark-file",
            "/private/quality.json",
            "--supersede-epoch",
            "1" * 64,
        ]
        with mock.patch.object(
            sys, "argv", ["memoryctl", "--actor", "codex", *restart_args]
        ), mock.patch.object(
            module.subprocess, "run"
        ) as rejected, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(module.main(), 2)
            rejected.assert_not_called()

        with mock.patch.object(
            sys, "argv", ["memoryctl", "--actor", "migration", *restart_args, "--json"]
        ), mock.patch.object(
            module.subprocess, "run", return_value=completed
        ) as invoked:
            self.assertEqual(module.main(), 0)
        command = invoked.call_args.args[0]
        self.assertTrue(routed_target(command).endswith("agent_memory_shadow.py"))
        self.assertEqual(command[command.index("restart") - 1], "--json")
        self.assertEqual(command.count("--actor"), 1)

    def test_shadow_rejects_forwarded_actor_overrides_before_exec(self) -> None:
        module = load_memoryctl()
        restart_tail = [
            "restart",
            "--benchmark-file",
            "/private/quality.json",
            "--supersede-epoch",
            "1" * 64,
        ]
        attempts = (
            ["--actor", "migration", *restart_tail],
            ["--actor=migration", *restart_tail],
            ["--act", "migration", *restart_tail],
            ["--act=migration", *restart_tail],
            [*restart_tail, "--acto", "migration"],
        )
        for forwarded in attempts:
            with self.subTest(forwarded=forwarded), mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "codex", "shadow", *forwarded],
            ), mock.patch.object(
                module.subprocess, "run"
            ) as rejected, contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(module.main(), 2)
                rejected.assert_not_called()
                self.assertIn("shadow actor override is forbidden", stderr.getvalue())

        with mock.patch.object(
            sys,
            "argv",
            [
                "memoryctl",
                "--actor",
                "migration",
                "shadow",
                "status",
                "--actor=codex",
            ],
        ), mock.patch.object(
            module.subprocess, "run"
        ) as rejected, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(module.main(), 2)
            rejected.assert_not_called()

    def test_runtime_child_is_covered_by_shared_shadow_activity_lock(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        lock_states: list[tuple[str, bool]] = []

        @contextlib.contextmanager
        def activity_lock(*, enabled: bool = True):
            lock_states.append(("enter", enabled))
            try:
                yield
            finally:
                lock_states.append(("exit", enabled))

        def run_while_locked(*_args, **_kwargs):
            self.assertEqual(lock_states, [("enter", True)])
            return completed

        with mock.patch.object(
            sys,
            "argv",
            ["memoryctl", "--actor", "codex", "shadow", "status", "--json"],
        ), mock.patch.object(
            module, "runtime_shadow_activity_lock", side_effect=activity_lock
        ), mock.patch.object(
            module.subprocess, "run", side_effect=run_while_locked
        ):
            self.assertEqual(module.main(), 0)
        self.assertEqual(lock_states, [("enter", True), ("exit", True)])

        lock_states.clear()
        with mock.patch.object(
            sys,
            "argv",
            [
                "memoryctl",
                "--actor",
                "migration",
                "shadow",
                "restart",
                "--benchmark-file",
                "/private/quality.json",
                "--supersede-epoch",
                "1" * 64,
            ],
        ), mock.patch.object(
            module, "runtime_shadow_activity_lock", side_effect=activity_lock
        ), mock.patch.object(
            module.subprocess, "run", return_value=completed
        ):
            self.assertEqual(module.main(), 0)
        self.assertEqual(lock_states, [("enter", False), ("exit", False)])

    def test_source_wrapper_joins_configured_alternate_shadow_lock_domain(self) -> None:
        if os.name != "posix":
            self.skipTest("shared flock interoperability is validated on POSIX")
        module = load_memoryctl()
        with tempfile.TemporaryDirectory() as temporary:
            config_root = Path(temporary).resolve() / "managed-runtime"
            (config_root / "config").mkdir(parents=True, mode=0o700)
            (config_root / "config" / "runtime-anchor.json").write_text(
                "{}\n", encoding="utf-8"
            )
            alternate_shadow = config_root / "private-shadow-state"

            def configured_value(name: str, default: str = "") -> str:
                return {
                    "CONFIG_ROOT": str(config_root),
                    "SHADOW_STATE_DIR": str(alternate_shadow),
                }.get(name, default)

            with mock.patch.object(
                module, "env_value", side_effect=configured_value
            ), module.runtime_shadow_activity_lock(), mock.patch.object(
                shadow_runtime, "CONFIG_ROOT", config_root
            ), mock.patch.object(
                shadow_runtime, "SHADOW_ROOT", alternate_shadow
            ), mock.patch.dict(
                os.environ,
                {"AGENT_MEMORY_SHADOW_ACTIVITY_LOCK_TIMEOUT_SECONDS": "0"},
            ), self.assertRaisesRegex(
                shadow_runtime.ShadowGateError, "SHADOW_ACTIVITY_LOCK_BUSY"
            ):
                with shadow_runtime._shadow_activity_lock(exclusive=True):
                    self.fail("exclusive cutover lock unexpectedly bypassed shared task lock")

            self.assertTrue(
                (alternate_shadow / ".shadow-activity.lock").is_file()
            )
            self.assertFalse((config_root / "shadow").exists())

    def test_orphan_runtime_child_keeps_shared_shadow_activity_lock(self) -> None:
        if os.name != "posix":
            self.skipTest("wrapper-kill lock inheritance is validated on POSIX")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            config_root = root / "managed-runtime"
            shadow_root = config_root / "private-shadow-state"
            (config_root / "config").mkdir(parents=True, mode=0o700)
            # A source/local Runtime can be ready from its manifest before the
            # first shadow-start exists.  Its ordinary writer must already join
            # the lock domain so epoch 0 cannot overtake delayed activity.
            (config_root / "config" / "runtime-manifest.json").write_text(
                "{}\n", encoding="utf-8"
            )
            ready = root / "child-ready"
            release = root / "child-release"
            done = root / "child-done"
            target = root / "blocking-runtime-child.py"
            target.write_text(
                """from pathlib import Path
import os
import time

ready = Path(os.environ["SHADOW_LOCK_TEST_READY"])
release = Path(os.environ["SHADOW_LOCK_TEST_RELEASE"])
done = Path(os.environ["SHADOW_LOCK_TEST_DONE"])
ready.write_text(str(os.getpid()), encoding="utf-8")
try:
    while not release.exists():
        time.sleep(0.01)
finally:
    done.write_text("done\\n", encoding="utf-8")
""",
                encoding="utf-8",
            )
            helper = root / "invoke-memoryctl.py"
            helper.write_text(
                f"""import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path

path = Path({str(SCRIPTS_ROOT / "memoryctl")!r})
loader = importlib.machinery.SourceFileLoader("orphan_lock_memoryctl", str(path))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
module.assert_runtime_ready = lambda _command: {{"ready": True}}
module.COMMANDS["explain"] = Path(os.environ["SHADOW_LOCK_TEST_TARGET"])
sys.argv = ["memoryctl", "--actor", "migration", "explain", "TEST"]
raise SystemExit(module.main())
""",
                encoding="utf-8",
            )
            environment = {
                **os.environ,
                "AGENT_MEMORY_CONFIG_ROOT": str(config_root),
                "AGENT_MEMORY_SHADOW_STATE_DIR": str(shadow_root),
                "SHADOW_LOCK_TEST_READY": str(ready),
                "SHADOW_LOCK_TEST_RELEASE": str(release),
                "SHADOW_LOCK_TEST_DONE": str(done),
                "SHADOW_LOCK_TEST_TARGET": str(target),
            }
            wrapper = subprocess.Popen(
                [sys.executable, str(helper)],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                self.assertFalse(
                    next(shadow_root.glob("shadow-start-*.json"), None),
                    "test must exercise the pre-start lock boundary",
                )
                deadline = time.monotonic() + 5.0
                while not ready.exists() and time.monotonic() < deadline:
                    if wrapper.poll() is not None:
                        self.fail(
                            "wrapper exited before child readiness: "
                            f"returncode={wrapper.returncode!r}"
                        )
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "Runtime child did not become ready")
                wrapper.kill()
                wrapper.wait(timeout=5)

                with mock.patch.object(
                    shadow_runtime, "CONFIG_ROOT", config_root
                ), mock.patch.object(
                    shadow_runtime, "SHADOW_ROOT", shadow_root
                ), mock.patch.dict(
                    os.environ,
                    {"AGENT_MEMORY_SHADOW_ACTIVITY_LOCK_TIMEOUT_SECONDS": "0"},
                ), self.assertRaisesRegex(
                    shadow_runtime.ShadowGateError, "SHADOW_ACTIVITY_LOCK_BUSY"
                ):
                    with shadow_runtime._shadow_activity_lock(exclusive=True):
                        self.fail("orphan Runtime child lost its shared lock")
            finally:
                release.write_text("release\n", encoding="utf-8")
                if wrapper.poll() is None:
                    wrapper.kill()
                    wrapper.wait(timeout=5)

            deadline = time.monotonic() + 5.0
            while not done.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(done.exists(), "orphan Runtime child did not exit")
            with mock.patch.object(
                shadow_runtime, "CONFIG_ROOT", config_root
            ), mock.patch.object(
                shadow_runtime, "SHADOW_ROOT", shadow_root
            ), mock.patch.dict(
                os.environ,
                {"AGENT_MEMORY_SHADOW_ACTIVITY_LOCK_TIMEOUT_SECONDS": "0"},
            ):
                acquired = False
                deadline = time.monotonic() + 5.0
                while not acquired and time.monotonic() < deadline:
                    try:
                        with shadow_runtime._shadow_activity_lock(exclusive=True):
                            acquired = True
                    except shadow_runtime.ShadowGateError as exc:
                        self.assertEqual(str(exc), "SHADOW_ACTIVITY_LOCK_BUSY")
                        time.sleep(0.01)
                self.assertTrue(acquired, "orphan child did not release its shared lock")

    def test_content_migrate_routes_only_codex_or_claude_to_installed_bundle(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        for actor in ("codex", "claude"):
            with self.subTest(actor=actor), mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", actor, "content-migrate", "plan", "--json"],
            ), mock.patch.object(module.subprocess, "run", return_value=completed) as invoked:
                self.assertEqual(module.main(), 0)
                command = invoked.call_args.args[0]
                self.assertTrue(routed_target(command).endswith("agent_memory_content_migrate.py"))
                self.assertEqual(command[-4:], ["--actor", actor, "plan", "--json"])
        with mock.patch.object(
            sys,
            "argv",
            ["memoryctl", "--actor", "migration", "content-migrate", "plan", "--json"],
        ), mock.patch.object(module.subprocess, "run") as invoked, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(module.main(), 2)
            invoked.assert_not_called()

    def test_confirmation_issuer_is_human_only_and_keeps_request_off_argv(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.object(
            sys,
            "argv",
            [
                "memoryctl", "--actor", "human", "confirmation-capability",
                "issue", "--json",
            ],
        ), mock.patch.object(module.subprocess, "run", return_value=completed) as invoked:
            self.assertEqual(module.main(), 0)
            command = invoked.call_args.args[0]
            self.assertTrue(
                routed_target(command).endswith(
                    "agent_memory_confirmation_capability.py"
                )
            )
            self.assertEqual(
                command[-4:],
                ["--issuer-actor", "human", "--json", "issue"],
            )
            self.assertNotIn("proposal", " ".join(command))
        for actor in ("codex", "claude", "migration"):
            module = load_memoryctl()
            with self.subTest(actor=actor), mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl", "--actor", actor,
                    "confirmation-capability", "issue", "--json",
                ],
            ), mock.patch.object(module.subprocess, "run") as invoked, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(module.main(), 2)
                invoked.assert_not_called()

    def test_zvec_index_maintenance_requires_migration_actor(self) -> None:
        for flag_and_value in (
            ["--init"], ["--scan"], ["--prune"],
            ["--changed-file", "/private/Fact.md"],
            ["--i"], ["--sc"], ["--changed-f", "/private/Fact.md"],
        ):
            module = load_memoryctl()
            with self.subTest(flag=flag_and_value[0]), mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "codex", "zvec", *flag_and_value],
            ), mock.patch.object(module.subprocess, "run") as invoked, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(module.main(), 2)
                invoked.assert_not_called()
        module = load_memoryctl()
        with mock.patch.object(
            sys,
            "argv",
            ["memoryctl", "--actor", "migration", "zvec", "--scan", "--json"],
        ), mock.patch.object(
            module.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0),
        ) as invoked:
            self.assertEqual(module.main(), 0)
            invoked.assert_called_once()

    def test_ailu_central_allowlist_rejects_every_low_level_command(self) -> None:
        forbidden = (
            "search",
            "prewrite",
            "closeout",
            "audit",
            "audit-autorun",
            "claim",
            "claims",
            "claims-expire",
            "observe-deletion",
            "observe-committed",
            "doctor",
            "index",
            "zvec",
            "check",
            "decision-outcomes",
            "observe",
            "policy-benchmark",
            "intent",
        )
        for command_name in forbidden:
            module = load_memoryctl()
            with (
                self.subTest(command=command_name),
                mock.patch.object(
                    sys,
                    "argv",
                    ["memoryctl", "--actor", "ailu", command_name],
                ),
                mock.patch.object(module.subprocess, "run") as invoked,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(module.main(), 2)
                invoked.assert_not_called()

    def test_unknown_actor_is_rejected_by_the_runtime_parser(self) -> None:
        module = load_memoryctl()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "retired-client", "version", "--json"],
            ),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            module.parse_args()
        self.assertEqual(raised.exception.code, 2)

    def test_ailu_write_uses_only_the_plugin_session(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        environment = {
            "AGENT_MEMORY_SESSION_ID": "ailu-session",
            "CODEX_THREAD_ID": "outer-codex-session",
        }
        with (
            mock.patch.dict(module.os.environ, environment, clear=True),
            mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl",
                    "--actor",
                    "ailu",
                    "write",
                    "prepare",
                    "--json",
                ],
            ),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 0)

        command = invoked.call_args.args[0]
        self.assertTrue(routed_target(command).endswith("agent_memory_write.py"))
        actor_index = command.index("--actor")
        self.assertEqual(command[actor_index:actor_index + 2], ["--actor", "ailu"])
        self.assertNotIn("--session-id", command)
        self.assertNotIn("ailu-session", command)
        self.assertNotIn("outer-codex-session", command)
        self.assertIn("prepare", command)
        child_env = invoked.call_args.kwargs["env"]
        self.assertEqual(child_env["AGENT_MEMORY_SESSION_ID"], "ailu-session")

    def test_ailu_write_rejects_every_explicit_session_spelling(self) -> None:
        private_marker = "private-session-argv-probe-94731"
        variants = (
            ["--session-id", private_marker],
            [f"--session-id={private_marker}"],
            ["--session", private_marker],
            ["--sess", private_marker],
        )
        for variant in variants:
            module = load_memoryctl()
            stderr = io.StringIO()
            with (
                self.subTest(variant=variant[0]),
                mock.patch.object(
                    sys,
                    "argv",
                    [
                        "memoryctl",
                        "--actor",
                        "ailu",
                        "write",
                        "read-target",
                        *variant,
                    ],
                ),
                mock.patch.object(module.subprocess, "run") as invoked,
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(module.main(), 2)
            invoked.assert_not_called()
            self.assertNotIn(private_marker, stderr.getvalue())

    def test_ailu_retrieve_forwards_distinct_actor(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl",
                    "--actor",
                    "ailu",
                    "retrieve",
                    "--json",
                ],
            ),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 0)

        command = invoked.call_args.args[0]
        self.assertTrue(routed_target(command).endswith("agent_memory_retrieve.py"))
        self.assertEqual(command[-3:-1], ["--actor", "ailu"])
        self.assertEqual(command[-1:], ["--json"])
        self.assertNotIn("project query", command)

    def test_ailu_prewrite_is_not_a_public_command(self) -> None:
        module = load_memoryctl()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "ailu", "prewrite", "summary"],
            ),
            mock.patch.object(module.subprocess, "run") as invoked,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(module.main(), 2)
        invoked.assert_not_called()
        self.assertIn("may use only retrieve, write, or version", stderr.getvalue())

    def test_ailu_prewrite_rejects_named_model_asserter(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl",
                    "--actor",
                    "ailu",
                    "prewrite",
                    "summary",
                    "--asserted-by",
                    "opencode",
                ],
            ),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 2)
        invoked.assert_not_called()

    def test_ailu_closeout_is_not_a_public_command(self) -> None:
        module = load_memoryctl()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "ailu", "closeout", "--dry-run"],
            ),
            mock.patch.object(module, "host_session_id", return_value=""),
            mock.patch.object(module.subprocess, "run") as invoked,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(module.main(), 2)
        invoked.assert_not_called()
        self.assertIn("may use only retrieve, write, or version", stderr.getvalue())

    def test_ailu_prewrite_rejects_ambiguous_duplicate_asserters(self) -> None:
        module = load_memoryctl()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl",
                    "--actor",
                    "ailu",
                    "prewrite",
                    "summary",
                    "--asserted-by",
                    "user",
                    "--asserted-by",
                    "codex",
                ],
            ),
            mock.patch.object(module.subprocess, "run") as invoked,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(module.main(), 2)
        invoked.assert_not_called()

    def test_core_command_uses_current_python(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(sys, "argv", ["memoryctl", "--actor", "human", "doctor", "--json"]),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 0)

        command = invoked.call_args.args[0]
        self.assertEqual(command[0], sys.executable)
        self.assertTrue(routed_target(command).endswith("agent_memory_doctor.py"))
        self.assertEqual(command[-1:], ["--json"])

    def test_zvec_uses_configured_semantic_python(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)

        def configured(name: str, default: str = "") -> str:
            return "/configured/semantic/python" if name == "ZVEC_PYTHON" else default

        with (
            mock.patch.object(sys, "argv", ["memoryctl", "--actor", "codex", "zvec", "--report"]),
            mock.patch.object(module, "env_value", side_effect=configured),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 0)

        command = invoked.call_args.args[0]
        self.assertEqual(command[0], "/configured/semantic/python")
        self.assertTrue(routed_target(command).endswith("agent_memory_zvec_index.py"))
        self.assertEqual(command[-1:], ["--report"])

    def test_retrieval_benchmark_uses_semantic_python_with_isolation_and_site(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)

        def configured(name: str, default: str = "") -> str:
            return "/configured/semantic/python" if name == "ZVEC_PYTHON" else default

        with (
            mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "migration", "retrieval-benchmark", "--json"],
            ),
            mock.patch.object(module, "env_value", side_effect=configured),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
            mock.patch("agent_memory_observability.record_task_seen") as task_seen,
        ):
            self.assertEqual(module.main(), 0)

        command = invoked.call_args.args[0]
        self.assertEqual(command[0], "/configured/semantic/python")
        self.assertIn("-I", command)
        self.assertNotIn("-S", command)
        self.assertTrue(
            routed_target(command).endswith("agent_memory_retrieval_benchmark.py")
        )
        task_seen.assert_not_called()

    def test_retrieval_benchmark_requires_migration_actor(self) -> None:
        module = load_memoryctl()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "codex", "retrieval-benchmark", "--json"],
            ),
            mock.patch.object(module.subprocess, "run") as invoked,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(module.main(), 2)
        invoked.assert_not_called()
        self.assertIn("requires --actor migration", stderr.getvalue())

    def test_retrieval_benchmark_route_can_import_only_semantic_site_package(self) -> None:
        module = load_memoryctl()
        module.assert_runtime_ready = lambda _command: {"ready": False}
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            environment = root / "semantic-venv"
            # uv standalone CPython on macOS must keep its original executable
            # location so @rpath can resolve libpython.  A POSIX venv symlink
            # preserves that location; Windows venv launchers require copies.
            venv.EnvBuilder(
                with_pip=False,
                symlinks=os.name != "nt",
            ).create(environment)
            semantic_python = (
                environment / "Scripts" / "python.exe"
                if os.name == "nt"
                else environment / "bin" / "python"
            )
            site_packages = Path(
                subprocess.check_output(
                    [
                        str(semantic_python),
                        "-I",
                        "-c",
                        "import sysconfig;print(sysconfig.get_paths()['purelib'])",
                    ],
                    text=True,
                ).strip()
            )
            package_name = "agent_memory_semantic_site_probe_8d7c39"
            (site_packages / f"{package_name}.py").write_text(
                "VALUE = 'loaded-from-semantic-site'\n",
                encoding="utf-8",
            )
            probe = root / "benchmark-probe.py"
            probe.write_text(
                f"import {package_name} as package\n"
                "raise SystemExit(0 if package.VALUE == 'loaded-from-semantic-site' else 9)\n",
                encoding="utf-8",
            )
            module.COMMANDS["retrieval-benchmark"] = probe

            def configured(name: str, default: str = "") -> str:
                return str(semantic_python) if name == "ZVEC_PYTHON" else default

            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["memoryctl", "--actor", "migration", "retrieval-benchmark"],
                ),
                mock.patch.object(module, "env_value", side_effect=configured),
            ):
                self.assertEqual(module.main(), 0)

    def test_search_rejects_conflicting_explicit_agent_scope(self) -> None:
        module = load_memoryctl()
        module.assert_runtime_ready = lambda _command: {"ready": False}
        stderr = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl",
                    "--actor",
                    "codex",
                    "search",
                    "query",
                    "--agent-scope",
                    "claude",
                ],
            ),
            mock.patch.object(module.subprocess, "run") as invoked,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(module.main(), 2)
        invoked.assert_not_called()
        self.assertIn("conflicts with --actor codex", stderr.getvalue())

    def test_search_rejects_abbreviated_agent_scope_override(self) -> None:
        module = load_memoryctl()
        module.assert_runtime_ready = lambda _command: {"ready": False}
        stderr = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl",
                    "--actor",
                    "codex",
                    "search",
                    "query",
                    "--agent-s=claude",
                ],
            ),
            mock.patch.object(module.subprocess, "run") as invoked,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(module.main(), 2)
        invoked.assert_not_called()
        self.assertIn("abbreviations are forbidden", stderr.getvalue())

    def test_search_canonicalizes_matching_explicit_agent_scope(self) -> None:
        module = load_memoryctl()
        module.assert_runtime_ready = lambda _command: {"ready": False}
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl",
                    "--actor",
                    "claude",
                    "search",
                    "query",
                    "--agent-scope=claude",
                ],
            ),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 0)
        command = invoked.call_args.args[0]
        self.assertNotIn("--agent-scope=claude", command)
        scope_index = command.index("--agent-scope")
        self.assertEqual(command[scope_index + 1], "claude")

    def test_explicit_session_is_stable_task_fallback_but_host_session_wins(self) -> None:
        module = load_memoryctl()
        keys = (
            "AGENT_MEMORY_TASK_ID",
            "AGENT_MEMORY_SESSION_ID",
            "CODEX_THREAD_ID",
        )
        clean = {key: os.environ.pop(key, None) for key in keys}
        try:
            first = module.invocation_task_id("codex", "explicit-session")
            second = module.invocation_task_id("codex", "explicit-session")
            self.assertEqual(first, "explicit-session")
            self.assertEqual(second, "explicit-session")
            self.assertEqual(os.environ["AGENT_MEMORY_TASK_ID"], "explicit-session")

            os.environ.pop("AGENT_MEMORY_TASK_ID", None)
            os.environ["CODEX_THREAD_ID"] = "real-host-thread"
            self.assertEqual(
                module.invocation_task_id("codex", "ordinary-explicit-session"),
                "real-host-thread",
            )
            self.assertNotIn("AGENT_MEMORY_TASK_ID", os.environ)
        finally:
            for key in keys:
                os.environ.pop(key, None)
            for key, value in clean.items():
                if value is not None:
                    os.environ[key] = value

    def test_agent_closeout_without_session_fails_closed(self) -> None:
        module = load_memoryctl()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "claude", "closeout", "--dry-run"],
            ),
            mock.patch.object(module, "host_session_id", return_value=""),
            mock.patch.object(module.subprocess, "run") as invoked,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(module.main(), 2)

        invoked.assert_not_called()
        self.assertIn("requires an active host session", stderr.getvalue())

    def test_explicit_session_closeout_is_always_claim_scoped(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "memoryctl",
                    "--actor",
                    "claude",
                    "closeout",
                    "--dry-run",
                    "--session-id",
                    "explicit-session",
                ],
            ),
            mock.patch.object(module, "host_session_id", return_value=""),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 0)

        command = invoked.call_args.args[0]
        self.assertIn("--session-id", command)
        self.assertIn("explicit-session", command)
        self.assertIn("--claimed-only", command)

    def test_global_closeout_requires_explicit_global_flag(self) -> None:
        module = load_memoryctl()
        completed = subprocess.CompletedProcess([], 0)
        with (
            mock.patch.object(
                sys,
                "argv",
                ["memoryctl", "--actor", "claude", "closeout", "--global", "--dry-run"],
            ),
            mock.patch.object(module, "host_session_id", return_value=""),
            mock.patch.object(module.subprocess, "run", return_value=completed) as invoked,
        ):
            self.assertEqual(module.main(), 0)

        command = invoked.call_args.args[0]
        self.assertNotIn("--claimed-only", command)


if __name__ == "__main__":
    unittest.main()
