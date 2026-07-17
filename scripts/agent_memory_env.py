from __future__ import annotations

import os
import ast
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # pragma: no cover - Python 3.10 fallback for import-time clarity
    tomllib = None  # type: ignore[assignment]


RUNTIME_ROOT = Path(__file__).resolve().parents[1]
LOCAL_PATH_DEFAULTS: dict[str, tuple[str, ...]] = {
    "CONFIG_ROOT": (),
    "STATE_DB": ("state.sqlite",),
    "AUDIT_DB": ("audit_decisions.sqlite",),
    "CLOSEOUT_LOG": ("logs", "closeout.jsonl"),
    "AUDIT_RUN_LOG": ("logs", "audit_runs.jsonl"),
    "AUDIT_REPORT": ("reports", "latest-audit.json"),
    "INVARIANTS": ("config", "system-invariants.json"),
    "VECTOR_DIR": ("zvec", "memory_chunks_embeddinggemma_768"),
    "ZVEC_LOCK": ("locks", "zvec.lock"),
    "MODEL_MANIFEST": ("models", "embeddinggemma-300m", "model-manifest.json"),
    "DEPENDENCY_LOCK": ("requirements-vector.lock",),
}
CONFIG_KEYS: dict[str, tuple[str, ...]] = {
    "ROOT": ("memory_root",),
    "GIT_ROOT": ("git_root",),
    "CONFIG_ROOT": ("config_root",),
    "STATE_DB": ("state_db",),
    "AUDIT_DB": ("audit_db",),
    "CLOSEOUT_LOG": ("closeout_log",),
    "AUDIT_RUN_LOG": ("audit_run_log",),
    "AUDIT_REPORT": ("audit_report",),
    "INVARIANTS": ("invariants_file",),
    "PYTHON": ("python",),
    "USER_ID": ("user_id",),
    "AGENT_ID": ("agent_id",),
    "APP_ID": ("app_id",),
    "VECTOR_DIR": ("semantic_retrieval", "vector_dir"),
    "EMBEDDING_MODEL": ("semantic_retrieval", "embedding_model"),
    "EMBEDDING_DIM": ("semantic_retrieval", "embedding_dim"),
    "EMBEDDING_DEVICE": ("semantic_retrieval", "embedding_device"),
    "ZVEC_PYTHON": ("semantic_retrieval", "python"),
    "ZVEC_LOCK": ("semantic_retrieval", "lock_path"),
    "REQUIRE_LOCAL_MODEL": ("semantic_retrieval", "require_local_model"),
    "MODEL_MANIFEST": ("semantic_retrieval", "model_manifest"),
    "MODEL_REVISION": ("semantic_retrieval", "model_revision"),
    "DEPENDENCY_LOCK": ("semantic_retrieval", "dependency_lock"),
}
DEFAULT_HOME = Path.home()


def expand_path(value: str) -> Path:
    """Expand user/environment paths consistently on Unix and Windows."""
    if ("$HOME" in value or "${HOME}" in value) and not os.environ.get("HOME"):
        home = os.environ.get("USERPROFILE") or str(DEFAULT_HOME)
        value = value.replace("${HOME}", home).replace("$HOME", home)
    return Path(os.path.expandvars(value)).expanduser()


def config_path() -> Path:
    explicit = os.environ.get("AGENT_MEMORY_CONFIG_FILE", "").strip()
    if explicit:
        return expand_path(explicit).resolve()
    return RUNTIME_ROOT / "config" / "agent-memory.toml"


@lru_cache(maxsize=1)
def load_dotenv() -> dict[str, str]:
    path = RUNTIME_ROOT / ".env"
    if not path.is_file():
        return {}
    payload: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, raw_value = line.partition("=")
        key = key.strip()
        if not separator or not key.isidentifier():
            continue
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            try:
                parsed = ast.literal_eval(value)
            except (SyntaxError, ValueError):
                value = value[1:-1]
            else:
                value = str(parsed)
        payload[key] = value
    return payload


def parse_toml_fallback(text: str) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    section: tuple[str, ...] = ()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = tuple(part.strip() for part in line[1:-1].split(".") if part.strip())
            continue
        key, separator, raw_value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        raw_value = raw_value.strip()
        try:
            value: object = ast.literal_eval(raw_value)
        except (SyntaxError, ValueError):
            lowered = raw_value.lower()
            if lowered in {"true", "false"}:
                value = lowered == "true"
            else:
                try:
                    value = int(raw_value)
                except ValueError:
                    value = raw_value
        target = payload
        for part in section:
            child = target.setdefault(part, {})
            if not isinstance(child, dict):
                break
            target = child
        else:
            target[key] = value
    return payload


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    path = config_path()
    if not path.is_file():
        return {}
    try:
        if tomllib is not None:
            with path.open("rb") as handle:
                payload = tomllib.load(handle)
        else:
            payload = parse_toml_fallback(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def reset_config_cache() -> None:
    load_config.cache_clear()
    load_dotenv.cache_clear()


def config_value(name: str) -> object | None:
    keys = CONFIG_KEYS.get(name)
    if not keys:
        return None
    value: object = load_config()
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def local_path_default(name: str) -> str | None:
    suffix = LOCAL_PATH_DEFAULTS.get(name)
    if suffix is None:
        return None
    dotenv = load_dotenv()
    configured_root = (
        os.environ.get("AGENT_MEMORY_CONFIG_ROOT", "").strip()
        or str(config_value("CONFIG_ROOT") or "").strip()
        or dotenv.get("AGENT_MEMORY_CONFIG_ROOT", "").strip()
    )
    if configured_root:
        root = expand_path(configured_root)
    elif (RUNTIME_ROOT / "config" / "runtime-manifest.json").is_file():
        root = RUNTIME_ROOT
    else:
        root = RUNTIME_ROOT / ".agent-memory"
    return str(root.joinpath(*suffix))


def env_value(name: str, default: str = "") -> str:
    """Read environment, runtime TOML, local .env, then an isolated safe default."""
    value = os.environ.get(f"AGENT_MEMORY_{name}")
    if value not in (None, ""):
        return value
    configured = config_value(name)
    if configured not in (None, ""):
        return str(configured)
    dotenv_value = load_dotenv().get(f"AGENT_MEMORY_{name}")
    if dotenv_value not in (None, ""):
        return str(dotenv_value)
    local_default = local_path_default(name)
    if local_default is not None:
        return local_default
    return default
