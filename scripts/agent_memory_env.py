from __future__ import annotations

import os


def env_value(name: str, default: str = "") -> str:
    """Read one Agent Memory environment variable with an optional default."""
    value = os.environ.get(f"AGENT_MEMORY_{name}")
    if value not in (None, ""):
        return value
    return default
