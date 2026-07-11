from __future__ import annotations

import os


def env_value(name: str, default: str = "") -> str:
    """Read the Agent Memory variable first, then its legacy Codex alias."""
    primary = os.environ.get(f"AGENT_MEMORY_{name}")
    if primary not in (None, ""):
        return primary
    legacy = os.environ.get(f"CODEX_MEMORY_{name}")
    if legacy not in (None, ""):
        return legacy
    return default
