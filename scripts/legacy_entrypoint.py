from __future__ import annotations

import runpy
from pathlib import Path


LEGACY_TARGETS = {
    "codex_agent_evolution.py": "agent_memory_evolution.py",
    "codex_memory_audit.py": "agent_memory_audit.py",
    "codex_memory_audit_autorun.py": "agent_memory_audit_autorun.py",
    "codex_memory_check.py": "agent_memory_check.py",
    "codex_memory_closeout.py": "agent_memory_closeout.py",
    "codex_memory_doctor.py": "agent_memory_doctor.py",
    "codex_memory_index.py": "agent_memory_index.py",
    "codex_memory_retrieval_benchmark.py": "agent_memory_retrieval_benchmark.py",
    "codex_memory_search.py": "agent_memory_search.py",
    "codex_memory_stop_hook.py": "agent_memory_stop_hook.py",
    "codex_memory_zvec_index.py": "agent_memory_zvec_index.py",
}


def run_legacy(path: str) -> None:
    source = Path(path).resolve()
    target_name = LEGACY_TARGETS.get(source.name)
    if not target_name:
        raise SystemExit(f"Unknown legacy Agent Memory entrypoint: {source.name}")
    runpy.run_path(str(source.with_name(target_name)), run_name="__main__")
