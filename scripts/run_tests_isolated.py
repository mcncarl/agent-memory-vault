#!/usr/bin/env python3
"""Run the test suite against disposable Agent Memory paths.

The repository checkout and the installed Runtime are evidence, not test
fixtures.  This launcher gives the whole unittest process a temporary HOME,
Vault, config root, state database, audit database, logs, reports, locks, and
transition-marker path.  Individual tests may create narrower fixtures, but
they can no longer fall back to ``.agent-memory`` in the source checkout or to
the user's installed Runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_ROOT.parent


def _tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return digest.hexdigest()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8", errors="surrogateescape")
        digest.update(relative)
        if path.is_symlink():
            digest.update(b"L")
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        elif path.is_file():
            digest.update(b"F")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif path.is_dir():
            digest.update(b"D")
    return digest.hexdigest()


def _write_config(path: Path, *, vault: Path, runtime: Path) -> None:
    payload = (
        f'memory_root = "{vault.as_posix()}"\n'
        f'git_root = "{vault.as_posix()}"\n'
        f'config_root = "{runtime.as_posix()}"\n'
        f'state_db = "{(runtime / "state.sqlite").as_posix()}"\n'
        f'audit_db = "{(runtime / "audit.sqlite").as_posix()}"\n'
        f'audit_run_log = "{(runtime / "logs" / "audit.jsonl").as_posix()}"\n'
        f'audit_report = "{(runtime / "reports" / "audit.json").as_posix()}"\n'
        f'invariants_file = "{(runtime / "config" / "invariants.json").as_posix()}"\n'
        '\n[observability]\n'
        'enabled = true\n'
        '\n[semantic_retrieval]\n'
        'enabled = false\n'
        'semantic_mode = "off"\n'
    )
    path.write_text(payload, encoding="utf-8")


def _initialize_state(state_db: Path, *, script_root: Path) -> None:
    sys.path.insert(0, str(script_root))
    try:
        from agent_memory_intent import ensure_schema as ensure_intent_schema
        from agent_memory_index import init_db
        from agent_memory_evolution import init_db as init_evolution_db
        from agent_memory_state import install_search_log_privacy_guards

        with sqlite3.connect(state_db) as connection:
            ensure_intent_schema(connection)
            init_db(connection)
            init_evolution_db(connection)
            install_search_log_privacy_guards(connection)
            connection.commit()
    finally:
        sys.path.remove(str(script_root))


def _copy_source_checkout(target: Path) -> None:
    ignored_names = {
        ".agent-memory",
        ".venv",
        ".venv-vector",
        ".pytest_cache",
        "__pycache__",
        "build",
        "dist",
        "model-cache",
        "node_modules",
        "private",
        "secrets",
        "tmp",
        "vector-store",
        "zvec",
    }

    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in ignored_names or name.endswith(".pyc")}

    shutil.copytree(REPO_ROOT, target, symlinks=True, ignore=ignore)


def _git_init(vault: Path, env: dict[str, str]) -> None:
    commands = (
        ("init", "-q"),
        ("config", "user.name", "Agent Memory Test"),
        ("config", "user.email", "agent-memory-test@invalid.local"),
        ("add", "AGENTS.md", "INDEX.md"),
        ("commit", "-q", "-m", "test fixture"),
    )
    for arguments in commands:
        completed = subprocess.run(
            ["git", "-C", str(vault), *arguments],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"could not initialize disposable test Vault: {completed.stderr.strip()}"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "unittest_args",
        nargs=argparse.REMAINDER,
        help="arguments passed to python -m unittest (prefix with -- if needed)",
    )
    return parser.parse_args()


def main() -> int:
    if sys.version_info < (3, 10):
        requested = os.environ.get("AGENT_MEMORY_TEST_PYTHON", "").strip()
        candidates = [requested] if requested else []
        candidates.extend(("python3.13", "python3.12", "python3.11", "python3.10"))
        for candidate_name in candidates:
            candidate = shutil.which(candidate_name) if candidate_name else None
            if candidate and Path(candidate).resolve() != Path(sys.executable).resolve():
                os.execv(candidate, [candidate, str(Path(__file__).resolve()), *sys.argv[1:]])
        print(
            "TEST_PYTHON_TOO_OLD: Python 3.10+ is required; set AGENT_MEMORY_TEST_PYTHON",
            file=sys.stderr,
        )
        return 2
    args = parse_args()
    forwarded = list(args.unittest_args)
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    if not forwarded:
        forwarded = ["discover", "-s", "tests", "-v"]

    source_state = REPO_ROOT / ".agent-memory"
    source_state_before = _tree_fingerprint(source_state)
    with tempfile.TemporaryDirectory(prefix="agent-memory-tests-") as raw_root:
        root = Path(raw_root).resolve()
        isolated_repo = root / "source"
        _copy_source_checkout(isolated_repo)
        isolated_scripts = isolated_repo / "scripts"
        home = root / "home"
        runtime = root / "runtime"
        vault = root / "vault"
        config_dir = runtime / "config"
        for directory in (
            home,
            config_dir,
            runtime / "locks",
            runtime / "logs",
            runtime / "reports",
            vault,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                directory.chmod(0o700)

        (vault / "AGENTS.md").write_text("# Disposable test Vault\n", encoding="utf-8")
        (vault / "INDEX.md").write_text("# Memory Index\n", encoding="utf-8")
        transition_marker = config_dir / "runtime-transition.test.json"
        transition_marker.write_text(
            '{"schema_version":1,"phase":"ready"}\n',
            encoding="utf-8",
        )
        config_file = config_dir / "agent-memory.toml"
        _write_config(config_file, vault=vault, runtime=runtime)
        (config_dir / "invariants.json").write_text("{}\n", encoding="utf-8")
        _initialize_state(runtime / "state.sqlite", script_root=isolated_scripts)
        if os.name == "posix":
            for private_file in (
                transition_marker,
                config_file,
                config_dir / "invariants.json",
                runtime / "state.sqlite",
            ):
                private_file.chmod(0o600)

        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("AGENT_MEMORY_")
        }
        env.update(
            {
                "HOME": str(home),
                "USERPROFILE": str(home),
                # Executable source entrypoints use ``/usr/bin/env python3``.
                # Keep child processes on the same supported interpreter as
                # the parent test run instead of falling back to macOS 3.9.
                "PATH": os.pathsep.join(
                    [str(Path(sys.executable).parent), env.get("PATH", "")]
                ).rstrip(os.pathsep),
                "AGENT_MEMORY_TEST_ISOLATED": "1",
                # Source-checkout commands use the production configuration
                # resolver. Point it at the disposable, fully initialized
                # state so readiness checks exercise the real fail-closed
                # path without touching repository-local or installed state.
                "AGENT_MEMORY_CONFIG_FILE": str(config_file),
                "AGENT_MEMORY_TEST_CONFIG_FILE": str(config_file),
                "AGENT_MEMORY_TEST_ROOT": str(vault),
                "AGENT_MEMORY_TEST_STATE_DB": str(runtime / "state.sqlite"),
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUTF8": "1",
            }
        )
        # Prevent a developer's global Git hooks or identity from influencing
        # the disposable Vault.  The test identity is configured locally.
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        existing_pythonpath = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = os.pathsep.join(
            item
            for item in (str(isolated_repo / "tests"), existing_pythonpath)
            if item
        )
        _git_init(vault, env)

        completed = subprocess.run(
            [sys.executable, "-m", "unittest", *forwarded],
            cwd=isolated_repo,
            env=env,
            check=False,
        )
        source_state_after = _tree_fingerprint(source_state)
        if source_state_after != source_state_before:
            print(
                "TEST_ISOLATION_BREACH: source .agent-memory changed during the test run",
                file=sys.stderr,
            )
            return 2
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
